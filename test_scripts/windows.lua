local file = loadfile("windows_list.lua")
file()
local windows = get_table()
local io = require "io"
local function get_windows_version(majversion,minversion,build,typeof)
  if  majversion == "" then 
    return 'Major Version Needed'   
  end  	
  if minversion=="" then
    return 'Minor Version Needed'
  end
  build = build or ""
  typeof = typeof or ""
  local result = ""	
  for i=1,70 do 
  	if tonumber(windows[i]['minversion']) == tonumber(minversion) and tonumber(windows[i]['majversion']) ==  tonumber(majversion)   and (build == "" or tonumber(windows[i]['build'])==tonumber(build)) and (typeof=="" or tostring(windows[i]['type']) == tostring(typeof)) then
  		result = result .. tostring(windows[i]['name']) .. '\n' 
  	end	
   end	
  return result	           
end
-- driver function to run the script --
repeat 
	io.write('enter majversion - >')
	io.flush()
	local majversion = io.read()
	io.write('enter minversion- >')
	io.flush()
	local minversion = io.read()
	io.write('enter build or leave blank- >')
	io.flush()
	local build = io.read()
	io.write('enter typeof or leave blank- >')
	io.flush()
	local typeof= io.read()
	local result =(get_windows_version(majversion,minversion,build,typeof))
	if result == "" then
		print('not found\n')
	else
		print(result)	
	end		
	io.write("continue with this operation (y/n)? ")
   	io.flush()
   	local answer=io.read()
until answer=="n" 
