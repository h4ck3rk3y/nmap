local http = require "http"
local io = require "io"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local os = require "os"

description = [[
Some webpages have exposed awstats folders. This gives easy access to a lot of information about the website such as :
->Number of Times Pages Were Visited
->Hours Spent on Pages
->IP address of People Who Accessed the Pages
->Data about robots that visited the pages.
->Worm Hits,Os Hits,Browser Hits,Referrers,Search-Queries
and more.
]]

--@args download set to true if you want nmap to download the logs for you.
--@args path where do you want  the file to be downloaded?
--@args break-on how many log files wanted?

--@usage nmap -p 80 --script http-awstats-info --script-args break-on=5,download=true,path='/home/example/' example.com -d
--@output
-- | http-awstats-info: 
-- | The Following Log Files Were Found!
-- |   awstats032015.example.com.txt
-- |   awstats022015.example.com.txt
-- |   awstats012015.example.com.txt
-- |   awstats122014.example.com.txt
-- |_  awstats112014.example.com.txt



author = "Gyanendra Mishra"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}



portrule = shortport.service("http")

local function  saveFile(path_to_save,data,filename)
  local path = path_to_save .. filename
  local file = io.open(filename,'w')
  if not file then  
    stdnse.print_debug(1,"File Not Being Opened. Ensure forward/backward slash at the end.")
  end  
  file:write(data)
  file:close()
end

action = function(host, port)
  local result = {}
  local txt_files = {}
  local all = {}
  
  --a boolean to check whether files should be downloaded or not
  local download = stdnse.get_script_args(SCRIPT_NAME .. ".download") or false
  --max number of files to be downloaded/checked
  local break_on = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".break-on")) or 5
  local path_to_save = stdnse.get_script_args(SCRIPT_NAME .. ".path") or ''
  --path of awstat installation
  local root = stdnse.get_script_args(SCRIPT_NAME .. ".root") or ""
  if download and not(path_to_save) then
    stdnse.format_output(false,"Download Set To True But no Destination Provided.")
  end

  local month = os.date('%m')
  local year  = os.date('%Y')

  local target_name = host.targetname

  if not(target_name) then
    return stdnse.format_output(false,"Please enter name of the website instead of the ip address.")
  end

  local target = root .. '/awstats/data/awstats' .. month .. year .. '.' .. target_name  .. '.txt'  
  target = target:gsub('//','/')
  --check if its vulnerable
  local response = http.get(host,port,target) 
  
  if response.status~=200 then
    return stdnse.format_output(false,"Site not vulnerable.")
  end

  local var
  
  month = month + 1
  
  for var=1,break_on do
    if month - 1 == 0 then
        month = 12
        year = year -1
    else 
      month = month -1         
    end 
    if month < 10 then
      target = root .. '/awstats/data/awstats0' .. month .. year .. '.' .. target_name  .. '.txt'
      table.insert(txt_files,'awstats0' .. month .. year .. '.' .. target_name  .. '.txt')
    else
      target = root .. '/awstats/data/awstats' .. month .. year .. '.' .. target_name  .. '.txt'
      table.insert(txt_files,'awstats' .. month .. year .. '.' .. target_name  .. '.txt')
    end
    target = target:gsub('//','/')
    all = http.pipeline_add(target, nil, all, "GET")
  end

  -- release hell...
  local pipeline_returns = http.pipeline_go(host, port, all)
  
  if not pipeline_returns then
    stdnse.print_debug(1,"got no answers from pipelined queries")
  end

  -- at times pipeline_returns is a nil object instead of a table
  if type(pipeline_returns) ~= 'table' then
    return nil
  end  

  -- if things look sweet then
  for i, data in pairs(pipeline_returns) do
    -- if it's not a four-'o-four, it probably means that the file is present
    if data.status==200 then
      stdnse.print_debug(1,"Found a file: %s",txt_files[i])
      table.insert(result,txt_files[i])
      if download then
        saveFile(path_to_save,data.body,txt_files[i])
      end  
    end
  end

  if #result > 0 then
    result.name = "The Following Log Files Were Found!"
    return stdnse.format_output(true, result)
  else
    return "Nothing found the page is probably protected"
  end
end