local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local base64 = require "base64"

description = [[
A script to detect WebDAV installations and find if it has insecure permsisions.
It's based on the  script ideas page.
  *https://secwiki.org/w/Nmap/Script_Ideas#	http-webdav
This script takes inspiration from the various metasploit modules listed here:
  *http://carnal0wnage.attackresearch.com/2010/05/more-with-metasploit-and-webdav.html
  *https://github.com/sussurro/Metasploit-Tools/blob/master/modules/auxiliary/scanner/http/webdav_test.rb
  *http://code.google.com/p/davtest/
]]

---
-- @usage
-- nmap --script http-iis-webdav-vuln -p80,8080 <host>
--
-- @output
-- 80/tcp open  http    syn-ack
-- |_ http-iis-webdav-vuln: WebDAV is ENABLED. Vulnerable folders discovered: /secret, /webdav
--
-- @args folder The folder to start in; eg, <code>"/web"</code> will try <code>"/web/xxx"</code>.
-----------------------------------------------------------------------

author = "Gyanendra Mishra"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "default"}


portrule = shortport.http

files = {
    ['asp'] = '<html><body><% response.write (!N1! * !N2!) %>',
    ['aspx'] = '<html><body><% response.write (!N1! * !N2!) %>',
    ['cfm'] = '<cfscript>WriteOutput(!N1!*!N2!);</cfscript>',
    ['cgi'] = "#!/usr/bin/perl\nprint \"Content-Type: text/html\n\r\n\r\" . !N1! * !N2!;",
    ['html'] = '!S1!<br />',
    ['jhtml'] = '<%= System.out.println(!N1! * !N2!); %>',
    ['jsp'] = '<%= System.out.println(!N1! * !N2!); %>',
    ['php'] = '<?php print !N1! * !N2!;?>',
    ['pl'] = "#!/usr/bin/perl\nprint \"Content-Type: text/html\n\r\n\r\" . !N1! * !N2!;",
    ['shtml'] = '<!--#echo var="DOCUMENT_URI"--><br /><!--#exec cmd="echo !S1!"-->',
    ['txt'] = '!S1!'
  }

jpg_file = base64.dec("/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAAA//EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AR//Z")

local function get_options(host, port, path)
  local options = {
  header = {
    ["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
  },
  }
  -- check if WebDav is installed or not.
  local response = http.generic_request(host, port, "OPTIONS", path, options)
  if response and response.status == 200 then
    ret = {}
    ret['name'] = "General Information"
    ret['server_type'] = response.header['server']
    ret['options_allowed'] = response.header['allow']
    ret['options_public'] = response.header['public']
    ret['webdav'] = false
    
    if response.header['dav'] and response.header['ms-author-via']:match('DAV') then
      ret['webdav'] = true
      ret['webdav_type'] = 'unkown'
      if response.header['X-MSDAVEXT'] then
        ret['webdav_type'] = 'SHAREPOINT DAV'
      end
      if response.header['dav']:match('apache') then
        ret['webdav_type'] = 'Apache DAV'
      end    
    end
    return ret
  
  else
    return false
  end
end

local function getIPs(body)
  ip_pat1 = '(192.168.%d+.%d+)'
  ip_pat2 = '(10.%d+.%d+.%d+)'
  ip_pat3 = '(172.%d.%d+.%d+)'
  ip_pats = {ip_pat1, ip_pat2, ip_pat3}
  result = {}
  for _,ip_pat in pairs(ip_pats) do
    local i = 1
    local ip
    while true do
      _, i, ip = body:find(ip_pat, i)
      if ip then
        table.insert(result, dir)
      else
        break
      end
    end
  end
  return result
end  

local function check_propfind(host, port, path)
  local options = {
  header = {
    ["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
    ["Depth"] = 1,
    ["Content-Length"] = 0
  }
  }
  local response = http.generic_request(host, port, "PROPFIND", path, options)
  if response and response.status ~= 207 then
    return false
  end
  ret = {}
  ret['success'] = false
  ret['ips'] = {}
  ret['dirs'] = {}
  
  dir_pat = '<.*[hH][rR][eE][fF][^>]*>(.*)</.*[hH][rR][eE][fF]>'
  if response.body:find('<D:status>HTTP%/1%.1 200 OK<%/D:status>') then
    ret['success'] = true
  end
  ret['ips'] = getIPs(response.body)
  local i = 1
  for dir in response.body:gmatch(dir_pat) do
  	table.insert(ret['dirs'], dir)
  end
  return ret
end

local function create_dir(host, port, dir)
 local options = {
  header = {
    ["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
    ["Content-Length"] = 0
  }
  }
  response = http.generic_request(host, port , 'MKCOL', dir, options)
  
  if response and response.status and response.status >= 200 and response.status <= 300 then
    return true
  end
  return false
end

local function delete_dir(host, port, dir)
  local options = {
  header = {
    ["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
    ["Content-Length"] = 0
  }
  }
  response = http.generic_request(host, port , "DELETE", dir, options)
  if response and response.status >= 200 and response.status <= 300 then
    return true
  end
  return false
end

local function check_extensions(host, port, path)
  local result = {}
  for extension, payload in pairs(files) do
  	stdnse.debug2('Trying to upload extension %s', extension)
    local answer = nil
    local fname = stdnse.generate_random_string(15, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    local file_path = path .. "/" .. fname .. "." .. extension
    if payload:find('!N1!') then
      local n1 = math.random(10000)/100 * 10
      local n2 = math.random(10000)/100 * 10
      answer = tostring(n1*n2)
      payload = payload:gsub('!N1', n1)
      payload = payload:gsub('!N2', n2)
    else
      answer = stdnse.generate_random_string(25, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
      payload = payload:gsub( '!S1!', answer)
    end
    payload = payload .. "\n\n"
    local options = {
    header = {
      ["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
      ["Content-Length"] = payload:len()
    },
    timeout = 10
    }
    local response = http.put(host, port, file_path, options, payload)
    if not response or response.status ~= 201 then
      table.insert(result, {extension, false, false})
    else
      response = http.get(host, port, file_path)
      if not response or response.status ~= 200 or not response.body:find(answer) or response.body:find("#exec") then
        table.insert(result, {extension, true, false})
      else
        table.insert(result, {extension, true, true})
      end  
    end
  end  
  return result
end

local function  check_rename(host, port, path)
  local result = {}
  for extension, payload in pairs(files) do
  	stdnse.debug2("Trying to rename extension %s", extension)
    local answer = nil
    local fname = stdnse.generate_random_string(15, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    local file_path = path .. "/" .. fname .. ".txt"
    file_path = file_path:gsub('//', '/')
    local file_path_move = nil
    
    if host.targetname then
      file_path_move = host.targetname .. "/" .. path .. "/" .. fname .. "." .. extension .. ';.jpg'
    else
      file_path_move = host.ip .. "/" .. path .. "/" .. fname .. "." .. extension .. ';.jpg'
    end
    file_path_move = 'http://' .. file_path_move:gsub('//', '/')
    if payload:find('!N1!') then
      local n1 = math.random(10000)/100 * 10
      local n2 = math.random(10000)/100 * 10
      answer = tostring(n1*n2)
      payload = payload:gsub('!N1', n1)
      payload = payload:gsub('!N2', n2)
    else
      answer = stdnse.generate_random_string(25, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
      payload = payload:gsub( '!S1!', answer)
    end

    payload = jpg_file .. payload .. '\n\n'
    local options = {
    header = {
      ["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
      ["Content-Length"] = payload:len()
    },
    timeout = 5
    }
    local response = http.put(host, port, file_path, options, payload)
    if not response or response.status ~= 201 then
      table.insert(result, {extension, false, false})
    else  
      options = {
      header = {
        ["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
        ["Destination"] = file_path_move
      },
      timeout = 5
      }
      print(file_path_move)
      response = http.generic_request(host, port, "MOVE", file_path, options)
      if not response or response.status ~= 204 then
        table.insert(result, {extension, true, false})
      else
        response = http.get(host, port, file_path .. ';.jpg')
        if not response or response.status ~= 200 or not response.body:find(answer) or response.body:find("#exec") then
          table.insert(result, {extension, true, false})
        else
          table.insert(result, {extension, true, true})
        end
      end
    end
  end
  return result
end

action = function(host, port)
  
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".folder") or '/'
  local enabled = false
  local output  = {}
  local temp_op = {}

  local info = get_options(host, port, path)
  if(info) then
    if(info['webdav']) then
      enabled = true
      stdnse.debug1("Target has %s server and %s ENABLED.", info['server_type'], info['webdav_type'])
      stdnse.debug1("Target allows following methods %s", tostring(info['options_allowed']))
      temp_op['name'] = 'Server Type'
      table.insert(temp_op, info['server_type'])
      table.insert(output, temp_op)
      temp_op = {}
      temp_op['name'] = 'WebDav Type'
      table.insert(temp_op, info['webdav_type'])
      table.insert(output, temp_op)
      temp_op = {}
      temp_op['name'] = 'Allowed Methods'
      table.insert(temp_op, info['options_allowed'])
      table.insert(output, temp_op)
      if info['options_public'] then
        stdnse.debug1("Target allows following public options %s", tostring(info['options_public']))
        temp_op = {}
      	temp_op['name'] = 'Public Methods'
      	table.insert(temp_op, info['options_public'])
      	table.insert(output, temp_op)
      end
    else
      stdnse.debug1("Target isn't reporting WebDav")
    end
  end

  local davinfo = check_propfind(host, port, path)
  if(davinfo) then
    if (davinfo['success'] and not(enabled)) then
      stdnse.debug1("Target has DAV enabled")
    end
    if #davinfo['ips']>0 then
      stdnse.debug1("The following IPs are publicly exposed.")
      for _,ip in pairs(davinfo['ips']) do
        stdnse.debug1("%s", tostring(ip))
      end
    end
    if #davinfo['dirs'] > 0 then
      stdnse.debug1("The following paths are public.")
      for _,dir in pairs(davinfo['dirs']) do
        stdnse.debug1("%s", tostring(dir))
      end
    end
    output['davinfo'] = davinfo
  end

  local random_string  = stdnse.generate_random_string(10, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
  local test_dir = path .. '/' .. 'WebDavTest_' .. random_string
  test_dir = test_dir:gsub('//', '/')
  stdnse.debug1("Attempting to create folder %s", test_dir)
  if create_dir(host, port, test_dir) then
    stdnse.debug1("The HOST is WRITABLE")
  else
    stdnse.debug1("The HOST is not WRITABLE")
    return stdnse.format_output(false, output)
  end

  stdnse.debug1("Checking extensions for upload and execution")
  local results_1 = check_extensions(host, port, test_dir)

  stdnse.debug1("Checking if rename is possible or not")
  local results_2 = check_rename(host, port, test_dir)

  stdnse.debug1("Deleting directory %s", test_dir)
  -- delete_dir(host, port, test_dir)

  local uploadable = {}
  uploadable['name'] = "Uploadable Files"
  local executable = {}
  executable['name'] = "Executable Files"
  local renameable = {}
  renameable['name'] = "Renameable Files"

  for _, result in pairs(results_1) do
    if result[2] == true then
      table.insert(uploadable, result[1])
    end
    if result[3] == true then
      table.insert(executable, result[1])
    end
  end

  for _,result in pairs(results_2) do
    if result[3] == true then
      table.insert(renameable, extension)
    end
  end

  table.insert(output, uploadable)
  table.insert(output, executable)
  table.insert(output, renameable)
  return stdnse.format_output(true, output)
end

