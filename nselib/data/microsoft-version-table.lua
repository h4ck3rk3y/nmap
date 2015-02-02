local table = require "table"
local io  =  require "io"
local stdnse = require "stdnse"
description = [[Performs version check for Windows and returns the long name of the WINDOWS OS
]]
--
--@usage 
--get_windows_name(majorversion,minorversion,<build>,<typeof>)
--arguments in <> are optional
--returns a table of possible names

author = "Gyanendra Mishra <anomaly.the@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
category = {"safe"}

-- a table of windows versions
local windows = {
{
	["name"]="Windows 95 OEM Service Release 1 (95A)",
	["majversion"] ="4",
	["minversion"] ="00",
	["build"] ="950 A",
	["type"] ="Client",
},
{
	["name"]="Windows 95 OEM Service Release 2 (95B)",
	["majversion"] ="4",
	["minversion"] ="00",
	["build"] ="1111 B",
	["type"] ="Client",
},
{
	["name"]="Windows 95 OEM Service Release 2.1",
	["majversion"] ="4",
	["minversion"] ="03",
	["build"] ="1212-1214 B",
	["type"] ="Client",
},
{
	["name"]="Windows 95 OEM Service Release 2.5 C",
	["majversion"] ="4",
	["minversion"] ="03",
	["build"] ="1214 C",
	["type"] ="Client",
},
{
	["name"]="Windows 98",
	["majversion"] ="4",
	["minversion"] ="10",
	["build"] ="1998",
	["type"] ="Client",
},
{
	["name"]="Windows 98 Second Edition (SE)",
	["majversion"] ="4",
	["minversion"] ="10",
	["build"] ="2222 A",
	["type"] ="Client",
},
{
	["name"]="Windows Millenium Beta",
	["majversion"] ="4",
	["minversion"] ="90",
	["build"] ="2476",
	["type"] ="Client",
},
{
	["name"]="Windows Millenium",
	["majversion"] ="4",
	["minversion"] ="90",
	["build"] ="3000",
	["type"] ="Client",
},
{
	["name"]="Windows NT 3.1",
	["majversion"] ="3",
	["minversion"] ="10",
	["build"] ="528 ",
	["type"] ="Client",
},
{
	["name"]="Windows NT 3.5",
	["majversion"] ="3",
	["minversion"] ="50",
	["build"] ="807 ",
	["type"] ="Client",
},
{
	["name"]="Windows NT 3.51",
	["majversion"] ="3",
	["minversion"] ="51",
	["build"] ="1057 ",
	["type"] ="Client",
},
{
	["name"]="Windows NT 4.00",
	["majversion"] ="4",
	["minversion"] ="00",
	["build"] ="1381 ",
	["type"] ="Client",
},
{
	["name"]="Windows NT 5.00 (Beta 2)",
	["majversion"] ="5",
	["minversion"] ="00",
	["build"] ="1515",
	["type"] ="Client",
},
{
	["name"]="Windows 2000 (Beta 3)",
	["majversion"] ="5",
	["minversion"] ="00",
	["build"] ="2031",
	["type"] ="Client",
},
{
	["name"]="Windows 2000 (Beta 3 RC2)",
	["majversion"] ="5",
	["minversion"] ="00",
	["build"] ="2128",
	["type"] ="Client",
},
{
	["name"]="Windows 2000 (Beta 3)",
	["majversion"] ="5",
	["minversion"] ="00",
	["build"] ="2183",
	["type"] ="Client",
},
{
	["name"]="Windows 2000",
	["majversion"] ="5",
	["minversion"] ="00",
	["build"] ="2195 ",
	["type"] ="Client",
},
{
	["name"]="Whistler Server Preview",
	["majversion"] ="",
	["minversion"] ="",
	["build"] ="2250",
	["type"] ="Server",
},
{
	["name"]="Whistler Server alpha",
	["majversion"] ="",
	["minversion"] ="",
	["build"] ="2257",
	["type"] ="Server",
},
{
	["name"]="Whistler Server interim release",
	["majversion"] ="",
	["minversion"] ="",
	["build"] ="2267",
	["type"] ="Server",
},
{
	["name"]="Whistler Server interim release",
	["majversion"] ="",
	["minversion"] ="",
	["build"] ="2410",
	["type"] ="Server",
},
{
	["name"]="Windows XP (RC 1)",
	["majversion"] ="5",
	["minversion"] ="1",
	["build"] ="2505",
	["type"] ="Client",
},
{
	["name"]="Windows XP",
	["majversion"] ="5",
	["minversion"] ="1",
	["build"] ="2600 ",
	["type"] ="Client",
},
{
	["name"]="Windows XP, Service Pack 1",
	["majversion"] ="5",
	["minversion"] ="1",
	["build"] ="2600.1105",
	["type"] ="Client",
},
{
	["name"]="Windows XP, Service Pack 2",
	["majversion"] ="5",
	["minversion"] ="1",
	["build"] ="2600.2180",
	["type"] ="Client",
},
{
	["name"]="Windows XP, Service Pack 3",
	["majversion"] ="5",
	["minversion"] ="1",
	["build"] ="2600 ",
	["type"] ="Client",
},
{
	["name"]="Windows .NET Server interim",
	["majversion"] ="5",
	["minversion"] ="2",
	["build"] ="3541",
	["type"] ="Server",
},
{
	["name"]="Windows .NET Server Beta 3",
	["majversion"] ="5",
	["minversion"] ="2",
	["build"] ="3590",
	["type"] ="Server",
},
{
	["name"]="Windows .NET Server Release Candidate 1 (RC1)",
	["majversion"] ="5",
	["minversion"] ="2",
	["build"] ="3660",
	["type"] ="Server",
},
{
	["name"]="Windows .NET Server 2003 RC2",
	["majversion"] ="5",
	["minversion"] ="2",
	["build"] ="3718",
	["type"] ="Server",
},
{
	["name"]="Windows Server 2003 (Beta?)",
	["majversion"] ="5",
	["minversion"] ="2",
	["build"] ="3763",
	["type"] ="Server",
},
{
	["name"]="Windows Server 2003",
	["majversion"] ="5",
	["minversion"] ="2",
	["build"] ="3790 ",
	["type"] ="Server",
},
{
	["name"]="Windows Server 2003, Service Pack 1",
	["majversion"] ="5",
	["minversion"] ="2",
	["build"] ="3790.1180",
	["type"] ="Server",
},
{
	["name"]="Windows Server 2003",
	["majversion"] ="5",
	["minversion"] ="2",
	["build"] ="3790.1218",
	["type"] ="Server",
},
{
	["name"]="Windows Home Server",
	["majversion"] ="5",
	["minversion"] ="2",
	["build"] ="3790 ",
	["type"] ="Server",
},
{
	["name"]="Windows Longhorn",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5048",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Beta 1",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5112 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Community Technology Preview (CTP)",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5219 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, TAP Preview",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5259 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, CTP (Dezember)",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5270 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, CTP (Februar)",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5308 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, CTP (Refresh)",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5342 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, April EWD",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5365 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Beta 2 Previw",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5381 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Beta 2",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5384 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Pre-RC1",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5456 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Pre-RC1, Build 5472",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5472 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Pre-RC1, Build 5536",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5536 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, RC1",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5600.16384 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Pre-RC2",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5700 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Pre-RC2, Build 5728",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5728 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, RC2",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5744.16384 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Pre-RTM, Build 5808",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5808 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Pre-RTM, Build 5824",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5824 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Pre-RTM, Build 5840",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="5840 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, RTM (Release to Manufacturing)",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="6000.16386 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="6000 ",
	["type"] ="Client",
},
{
	["name"]="Windows Vista, Service Pack 2",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="6002 ",
	["type"] ="Client",
},
{
	["name"]="Windows Server 2008",
	["majversion"] ="6",
	["minversion"] ="0",
	["build"] ="6001 ",
	["type"] ="Server",
},
{
	["name"]="Windows 7, RTM (Release to Manufacturing)",
	["majversion"] ="6",
	["minversion"] ="1",
	["build"] ="7600.16385 ",
	["type"] ="Client",
},
{
	["name"]="Windows 7",
	["majversion"] ="6",
	["minversion"] ="1",
	["build"] ="7601",
	["type"] ="Client",
},
{
	["name"]="Windows Server 2008 R2, RTM (Release to Manufacturing)",
	["majversion"] ="6",
	["minversion"] ="1",
	["build"] ="7600.16385 ",
	["type"] ="Server",
},
{
	["name"]="Windows Server 2008 R2, SP1",
	["majversion"] ="6",
	["minversion"] ="1",
	["build"] ="7601",
	["type"] ="Server",
},
{
	["name"]="Windows Home Server 2011",
	["majversion"] ="6",
	["minversion"] ="1",
	["build"] ="8400 ",
	["type"] ="Server",
},
{
	["name"]="Windows Server 2012",
	["majversion"] ="6",
	["minversion"] ="2",
	["build"] ="9200 ",
	["type"] ="Server",
},
{
	["name"]="Windows 8",
	["majversion"] ="6",
	["minversion"] ="2",
	["build"] ="9200 ",
	["type"] ="Client",
},
{
	["name"]="Windows Phone 8",
	["majversion"] ="6",
	["minversion"] ="2",
	["build"] ="10211 ",
	["type"] ="Client",
},
{
	["name"]="Windows Server 2012 R2",
	["majversion"] ="6",
	["minversion"] ="3",
	["build"] ="9200 ",
	["type"] ="Server",
},
{
	["name"]="Windows 8.1",
	["majversion"] ="6",
	["minversion"] ="3",
	["build"] ="9200 ",
	["type"] ="Client",
},
{
	["name"]="Windows 8.1, Update 1",
	["majversion"] ="6",
	["minversion"] ="3",
	["build"] ="9600 ",
	["type"] ="Client",
},
}
function get_windows_name(majversion,minversion,build,typeof)
  if  majversion == "" then 
    stdnse.print_debug(1,"Major Version wasn't supplied.")
    return nil  
  end  	
  if minversion=="" then
    stdnse.print_debug(1,"Minor Version wasn't supplied.")
    return nil
  end
  build = build or ""
  typeof = typeof or ""
  local result = {}
  result['name'] = 'Possibly Windows : - > '
  for i,_ in ipairs(windows) do 
  	if tonumber(windows[i]['minversion']) == tonumber(minversion) and tonumber(windows[i]['majversion']) ==  tonumber(majversion)   and (build == "" or tonumber(windows[i]['build'])==tonumber(build)) and (typeof=="" or tostring(windows[i]['type']) == tostring(typeof)) then
  		 table.insert(result,windows[i]['name'])
  	end	
   end	
  return result	           
end

function  already_processed(server,done_list)
 for  _,v in pairs(done_list) do 
  if (v.version.major == server.version.major and v.version.minor == server.version.minor and v.name == server.name and v.type == server.type) then
   return true
  end
 end
 return false
end
			
