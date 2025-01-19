local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local creds = require "creds"
local unpwdb = require "unpwdb"
local smb = require "smb"
local ftp = require "ftp"
local brute = require "brute"
local libssh2_util = require "libssh2-utility"
local match = require "match"
local strbuf = require "strbuf"

description = [[
  Test login default credentials for remote protocols like SMB, FTP, SSH, and Telnet.
  The script reads the specified input CSV file passed as a script argument.
]]

author = "Your Name"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}

-- Function to parse the CSV file
local function parse_csv(file)
  local f = io.open(file, "r")
  if not f then
    return nil, "Failed to open file: " .. file
  end
  local data = {}
  for line in f:lines() do
    local os, creds = line:match("([^,]+),([^,]+)")
    if os and creds then
      table.insert(data, {os = os, creds = creds})
    end
  end
  f:close()
  return data
end

-- Function to test SMB credentials
local function test_smb(host, user, pass)
  local status, smbstate = smb.start(host)
  if not status then
    return false
  end

  status, err = smb.negotiate_protocol(smbstate, {})
  if not status then
    return false
  end

  status, err = smb.start_session(smbstate, {username = user, password = pass})
  if status then
    smb.disconnect(smbstate)
    return true
  end

  return false
end

-- Function to test FTP credentials
local function test_ftp(host, port, user, pass)
  local socket = brute.new_socket()
  local realsocket, code, message, buffer = ftp.connect(host, port, {request_timeout=5000})
  if not realsocket then
    stdnse.print_debug(1,"Couldn't connect to host: " .. (code or message) )
    return false
  end
  socket.socket = realsocket

  local buffer = stdnse.make_buffer(socket, "\r?\n")
  local status, code, message = ftp.auth(socket, buffer, user, pass)
  ftp.close(socket)

  if status then
    return true
  end
  return false
end

-- Function to test SSH credentials using ssh-brute functionality
local function test_ssh(host, port, user, pass)
  local Driver = {
    new = function (self, host, port, options)
      stdnse.debug(2, "creating brute driver")
      local o = {
        helper = libssh2_util.SSHConnection:new(),
      }
      setmetatable(o, self)
      self.__index = self
      o.host = host
      o.port = port
      o.options = options
      return o
    end,

    connect = function (self)
      local status, err = self.helper:connect_pcall(self.host, self.port)
      if not status then
        stdnse.debug(2, "libssh2 error: %s", self.helper.session)
        local err = brute.Error:new(self.helper.session)
        err:setReduce(true)
        return false, err
      elseif not self.helper.session then
        stdnse.debug(2, "failure to connect: %s", err)
        local err = brute.Error:new(err)
        err:setAbort(true)
        return false, err
      else
        self.helper:set_timeout(self.options.ssh_timeout)
        return true
      end
    end,

    login = function (self, username, password)
      stdnse.verbose(1, "Trying username/password pair: %s:%s", username, password)
      local status, resp = self.helper:password_auth(username, password)
      if status then
        return true, creds.Account:new(username, password, creds.State.VALID)
      end
      return false, brute.Error:new "Incorrect password"
    end,

    disconnect = function (self)
      return self.helper:disconnect()
    end,
  }

  local driver = Driver:new(host.ip, port, {ssh_timeout = 5000})
  local status, err = driver:connect()
  if not status then
    return false
  end

  status, account = driver:login(user, pass)
  driver:disconnect()

  return status
end

-- Function to test Telnet credentials
local function test_telnet(host, port, user, pass)
  -- Utility functions
  local is_username_prompt = function (str)
    local lcstr = str:lower()
    return lcstr:find("%f[%w]username%s*:%s*$")
        or lcstr:find("%f[%w]login%s*:%s*$")
        or lcstr:find("%f[%w]login as%s*:%s*$")
    end

  local is_password_prompt = function (str)
      local lcstr = str:lower()
      return lcstr:find("%f[%w]password%s*:%s*$")
          or lcstr:find("%f[%w]passcode%s*:%s*$")
    end

  local is_login_success = function (str)
      if str:find("^[A-Z]:\\") then                         -- Windows telnet
        return true
      end
      local lcstr = str:lower()
      return lcstr:find("[/>%%%$#]%s*$")                    -- general prompt
          or lcstr:find("^last login%s*:")                  -- linux telnetd
          or lcstr:find("%f[%w]main%smenu%f[%W]")           -- Netgear RM356
          or lcstr:find("^enter terminal emulation:%s*$")   -- Hummingbird telnetd
          or lcstr:find("%f[%w]select an option%f[%W]")     -- Zebra PrintServer
    end

  local is_login_failure = function (str)
      local lcstr = str:lower()
      return lcstr:find("%f[%w]incorrect%f[%W]")
          or lcstr:find("%f[%w]failed%f[%W]")
          or lcstr:find("%f[%w]denied%f[%W]")
          or lcstr:find("%f[%w]invalid%f[%W]")
          or lcstr:find("%f[%w]bad%f[%W]")
    end

  local remove_termcodes = function (str)
      local mark = '\x0B'
      return str:gsub('\x1B%[%??%d*%a', mark)
                :gsub('\x1B%[%??%d*;%d*%a', mark)
    end

  local Connection = { methods = {} }
  Connection.new = function (host, port, proto)
    local soc = brute.new_socket(proto)
    if not soc then return nil end
    return setmetatable({
                          socket = soc,
                          isopen = false,
                          buffer = nil,
                          error = nil,
                          host = host,
                          port = port,
                          proto = proto
                        },
                        {
                          __index = Connection.methods,
                          __gc = Connection.methods.close
                        })
  end

  Connection.methods.connect = function (self)
    local status
    local wait = 1

    self.buffer = ""

    for tries = 0, 3 do
      self.socket:set_timeout(5000)
      status, self.error = self.socket:connect(self.host, self.port, self.proto)
      if status then break end
      stdnse.sleep(wait)
      wait = 2 * wait
    end

    self.isopen = status
    return status, self.error
  end

  Connection.methods.close = function (self)
    if not self.isopen then return true, nil end
    local status
    self.isopen = false
    self.buffer = nil
    status, self.error = self.socket:close()
    return status, self.error
  end

  Connection.methods.send_line = function (self, line)
    local status
    status, self.error = self.socket:send(line .. "\r\n")
    return status, self.error
  end

  Connection.methods.fill_buffer = function (self, data)
    local outbuf = strbuf.new(self.buffer)
    local optbuf = strbuf.new()
    local oldpos = 0

    while true do
      -- look for IAC (Interpret As Command)
      local newpos = data:find('\255', oldpos, true)
      if not newpos then break end

      outbuf = outbuf .. data:sub(oldpos, newpos - 1)
      local opttype, opt = data:byte(newpos + 1, newpos + 2)

      if opttype == 251 or opttype == 252 then
        -- Telnet Will / Will Not
        -- regarding ECHO or GO-AHEAD, agree with whatever the
        -- server wants (or not) to do; otherwise respond with
        -- "don't"
        opttype = (opt == 1 or opt == 3) and opttype + 2 or 254
      elseif opttype == 253 or opttype == 254 then
        -- Telnet Do / Do not
        -- I will not do whatever the server wants me to
        opttype = 252
      end

      optbuf = optbuf .. string.char(255, opttype, opt)
      oldpos = newpos + 3
    end

    self.buffer = strbuf.dump(outbuf) .. data:sub(oldpos)
    self.socket:send(strbuf.dump(optbuf))
    return self.buffer:len()
  end

  Connection.methods.get_line = function (self)
    if self.buffer:len() == 0 then
      -- refill the buffer
      local status, data = self.socket:receive_buf(match.pattern_limit("[\r\n:>%%%$#\255].*", 2048), true)
      if not status then
        -- connection error
        self.error = data
        return nil
      end

      self:fill_buffer(data)
    end
    return remove_termcodes(self.buffer:match('^[^\r\n]*'))
  end

  Connection.methods.discard_line = function (self)
    self.buffer = self.buffer:gsub('^[^\r\n]*[\r\n]*', '', 1)
    return self.buffer:len()
  end

  stdnse.print_debug(1,"Creating connection")
  local conn = Connection.new(host, port, "tcp")
  if not conn then
    stdnse.print_debug(1, "Cannot create connection")
    return false
  end
  conn:connect()
  if conn.error then
    stdnse.print_debug(1,"Connection error")
    conn:close()
  end
  if not conn.isopen then
    stdnse.print_debug(1,"Connection not open")
    return false
  end

  if conn.isopen then
    stdnse.print_debug(1,"connected!")
  end

  local line
  repeat
    line = conn:get_line()
  until not line
        or is_username_prompt(line)
        or is_password_prompt(line)
        or not conn:discard_line()
  stdnse.print_debug(1,line)
  local pass_only = false
  if not line then return false end
  stdnse.print_debug(1,user)
  if is_username_prompt(line) and not conn:send_line(user) then
    return false
  elseif is_password_prompt(line) then
    if not conn:send_line(pass) then
      return false
    else
      pass_only = true
    end
  end
  conn:discard_line() -- remove user login line from local history
  repeat
    line = conn:get_line()
  until not line
        or is_username_prompt(line)
        or is_password_prompt(line)
        or is_login_success(line)
        or not conn:discard_line()
  stdnse.print_debug(1,line)
  if is_login_success(line) then --login without password
    conn:close()
    return true
  end
  if not pass_only then
    stdnse.print_debug(1,pass)
    if not conn:send_line(pass) then return false end
    conn:discard_line() -- remove password line from local history
  end

  repeat
    line = conn:get_line()
  until not line
        or is_username_prompt(line)
        or is_password_prompt(line)
        or is_login_success(line)
        or not conn:discard_line()
  stdnse.print_debug(1,"Received: "..line)
  if is_login_success(line) then
    conn:close()
    return true
  end

end

-- Main action function
action = function(host, port)
  local csv_file = stdnse.get_script_args("default-creds.csv")
  if not csv_file then
    return "Please specify the CSV file with --script-args default-creds.csv=<file>"
  end

  local data, err = parse_csv(csv_file)
  if not data then
    return err
  end

  local results = {}
  local hostos = nil
  if host.os ~= nil and (#host.os > 0) then
    hostos = host.os[1]
  else
    stdnse.print_debug(1,"os detection failed, try default credentials for "..host.ip)
    hostos = "default"
  end
  for _, entry in ipairs(data) do
    local os = entry.os
    if string.find(string.lower(hostos.name), os) then
      local user, pass = entry.creds:match("([^:]+):([^:]*)")
      if user and pass then
        stdnse.print_debug(1, "Testing host: %s, user: %s, pass: %s", host.ip, user, pass)
        if port.service == "microsoft-ds" and test_smb(host, user, pass) then
          if pass == "" then pass = "<blank>" end
          table.insert(results, string.format("creds for smb: %s:%s", user, pass))
        end
        if port.service == "ftp" and test_ftp(host, port, user, pass) then
          if pass == "" then pass = "<blank>" end
          table.insert(results, string.format("creds for ftp: %s:%s", user, pass))
        end
        if port.service == "ssh" and test_ssh(host, port, user, pass) then
          if pass == "" then pass = "<blank>" end
          table.insert(results, string.format("creds for ssh: %s:%s", user, pass))
        end
        if port.service == "telnet" and test_telnet(host, port, user, pass) then
          if pass == "" then pass = "<blank>" end
          table.insert(results, string.format("creds for telnet: %s:%s", user, pass))
        end
      end
    end
  end

  return table.concat(results, "\n")
end

-- Define the rule for when the script should run
portrule = shortport.port_or_service({21, 22, 23, 445}, {"ftp", "ssh", "telnet", "microsoft-ds"})