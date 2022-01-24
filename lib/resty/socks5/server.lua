local _VERSION = '0.1.3'

local bit = require "bit"
local byte = string.byte
local char = string.char
local sub = string.sub
local ngx_log = ngx.log
local ngx_exit = ngx.exit
local thread_spawn = ngx.thread.spawn

local DEBUG = ngx.DEBUG
local ERR = ngx.ERR
local ERROR = ngx.ERROR
local OK = ngx.OK

local SOCKS_VERSION = 0x05
local SUB_AUTH_VERSION = 0x01
local RSV = 0x00
local NOAUTH = 0x00
local GSSAPI = 0x01
local AUTH = 0x02
local IANA = 0x03
local RESERVED = 0x80
local NOMETHODS = 0xFF
local IPV4 = 0x01
local DOMAIN_NAME = 0x03
local IPV6 = 0x04
local CONNECT = 0x01
local BIND = 0x02
local UDP = 0x03
local SUCCEEDED = 0x00
local FAILURE = 0x01
local RULESET = 0x02
local NETWORK_UNREACHABLE = 0x03
local HOST_UNREACHABLE = 0x04
local CONNECTION_REFUSED = 0x05
local TTL_EXPIRED = 0x06
local COMMAND_NOT_SUPORTED = 0x07
local ADDRESS_TYPE_NOT_SUPPORTED = 0x08
local UNASSIGNED = 0x09


--[[
    ----+--------+
    |VER | METHOD |
    +----+--------+
    | 1  |   1    |
    +----+--------+
]]
local function _socks5_server_send_method(sock, method)
    local data = char(VERSION, method)
    return sock:send(data)
end

--[[
    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     | 1 to 255 |
    +----+----------+----------+
]]
local function _socks5_server_receive_methods(sock)
    local data, err = sock:receive(2)
    if not data then
        ngx_exit(ERROR)
        return nil, err
    end

    local ver = byte(data, 1)
    local nmethods = byte(data, 2)

    local methods, err = sock:receive(nmethods)
    if not methods then
        ngx_exit(ERROR)
        return nil, err
    end

    return {
        ver         = ver,
        nmethods    = nmethods,
        methods     = methods
    }
end

--[[
    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    --+----+-----+-------+------+----------+----------+
]]
local function _socks5_server_send_replies(sock, rep, atyp, addr, port)
    local data = { true, true, true }
    data[1] = char(VERSION)
    data[2] = char(rep)
    data[3] = char(RSV)

    if atyp then
        data[4] = atyp
        data[5] = addr
        data[6] = port
    else
        data[4] = char(IPV4)
        data[5] = "\x00\x00\x00\x00"
        data[6] = "\x00\x00"
    end

    return sock:send(data)
end

--[[
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
]]
local function _socks5_server_receive_requests(sock)
    local data, err = sock:receive(4)
    if not data then
        ngx_log(ERR, "failed to receive requests: ", err)
        return nil, err
    end

    local ver = byte(data, 1)
    local cmd = byte(data, 2)
    local rsv = byte(data, 3)
    local atyp = byte(data, 4)

    local dst_len = 0
    if atyp == DOMAIN_NAME then
        local data, err = sock:receive(1)
        if not data then
            ngx_log(ERR, "failed to receive domain name len: ", err)
            return nil, err
        end
        dst_len = byte(data, 1)
    elseif atyp == IPV4 then
        dst_len = 4
    elseif atyp == IPV6 then
        dst_len = 16
    else
        return nil, "unknow atyp " .. atyp
    end

    local data, err = sock:receive(dst_len + 2) -- port
    if err then
        ngx_log(ERR, "failed to receive DST.ADDR: ", err)
        return nil, err
    end

    local dst = sub(data, 1, dst_len)
    local port_2 = byte(data, dst_len + 1)
    local port_1 = byte(data, dst_len + 2)
    local port = port_1 + port_2 * 256

    return {
        ver     = ver,
        cmd     = cmd,
        rsv     = rsv,
        atyp    = atyp,
        addr    = dst,
        port    = port,
    }
end

--[[
    +----+------+----------+------+----------+
    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    +----+------+----------+------+----------+
    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    +----+------+----------+------+----------+
]]
local function _socks5_server_receive_auth(sock)
    local data, err = sock:receive(2)
    if err then
        return nil, err
    end

    local ver = byte(data, 1)
    local ulen = byte(data, 2)

    local data, err = sock:receive(ulen)
    if err then
        return nil, err
    end

    local uname = data

    local data, err = sock:receive(1)
    if err then
        return nil, err
    end

    local plen = byte(data, 1)

    local data, err = sock:receive(plen)
    if err then
        return nil, err
    end

    local passwd = data

    return {
        username = uname,
        password = passwd
    }
end

--[[
    +----+--------+
    |VER | STATUS |
    +----+--------+
    | 1  |   1    |
    +----+--------+
]]
local function _socks5_server_send_auth_status(sock, status)
    local data = { true, true }

    data[1] = char(SUB_AUTH_VERSION)
    data[2] = char(status)

    return sock:send(data)
end

local function _stringify_addr(atyp, addr)
    if atyp == IPV4 then
        dst = string.format("%d.%d.%d.%d",
                byte(data, 1),
                byte(data, 2),
                byte(data, 3),
                byte(data, 4)
                )
    elseif atyp == IPV6 then
        dst = string.format("[%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X]",
                byte(dst, 1), byte(dst, 2),
                byte(dst, 3), byte(dst, 4),
                byte(dst, 5), byte(dst, 6),
                byte(dst, 7), byte(dst, 8),
                byte(dst, 9), byte(dst, 10),
                byte(dst, 11), byte(dst, 12),
                byte(dst, 13), byte(dst, 14),
                byte(dst, 15), byte(dst, 16)
                )
    else
        return addr
    end
end

local function _socks5_server_auth()
    if username then
        local auth, err = _receive_auth(downsock)
        if err then
            ngx_log(ERR, "send method error: ", err)
            ngx_exit(ERROR)
            return false
        end

        local status = FAILURE
        if auth.username == username and auth.password == password then
            status = SUCCEEDED
        end

        local ok, err = send_auth_status(downsock, status)
        if err then
            ngx_log(ERR, "send auth status error: ", err)
            ngx_exit(ERROR)
            return false
        end

        if status == FAILURE then
            return false
        end
    end
end

local function _socks5_server_auth_method()

    return true
end

local function _socks5_server_noauth_method()
    return true
end

local _auth_methods = {
    [NOAUTH]    = _socks5_server_noauth_method,
    [AUTH]      = _socks5_server_auth_method
}

local function socks_pipe(src, dst)
    while true do
        local data, err, partial = src:receive('*b')
        if not data then
            if partial then
                dst:send(partial)
            end

            if err ~= 'closed' then
                ngx_log(ERR, "pipe receive the src get error: ", err)
            end

            break
        end

        local ok, err = dst:send(data)
        if err then
            ngx_log(ERR, "pipe send the dst get error: ", err)

            return
        end
    end
end

local function _socks5_server_run(self)
    local downsock, err = assert(ngx.req.socket(true))
    if not downsock then
        ngx_log(ERR, "failed to get the request socket: ", err)
        return ngx.exit(ERROR)
    end

    timeout = timeout or 1000
    downsock:settimeout(timeout)

    local negotiation, err = _receive_methods(downsock)
    if err then
        ngx_log(ERR, "receive methods error: ", err)
        ngx_exit(ERROR)
        return false
    end

    if negotiation.ver ~= SOCKS_VERSION then
        ngx_log(DEBUG, "only support version: ", VERSION)
        return ngx_exit(OK)
    end

    -- ignore client supported methods, we only support AUTH and NOAUTH
    -- for #i = 1, negotiation.methods + 1 then
    --     local method = byte(negotiation.methods, i)
    -- end

    local method = NOAUTH
    if username then
        method = AUTH
    end

    local ok, err = _send_method(downsock, method)
    if err then
        ngx_log(ERR, "send method error: ", err)
        ngx_exit(ERROR)
        return
    end

    -- SERVER AUTH

    local requests, err = _receive_requests(downsock)
    if err then
        ngx_log(ERR, "send request error: ", err)
        ngx_exit(ERROR)
        return
    end

    if requests.cmd ~= CONNECT then
        local ok, err = _send_replies(downsock, COMMAND_NOT_SUPORTED)
        if err then
            ngx_log(ERR, "send replies error: ", err)
            ngx_exit(ERROR)

        end
        return
    end

    local upsock = ngx.socket.tcp()
    upsock:settimeout(timeout)

    local addr = _stringify_addr(requests.atyp, requests.addr)
    local ok, err = upsock:connect(addr, requests.port)
    if err then
        ngx_log(ERR, "connect request " .. requests.addr ..
            ":" .. requests.port .. " error: ", err)
        ngx_exit(ERROR)
        return
    end

    local ok, err = send_replies(downsock, SUCCEEDED)
    if err then
        ngx_log(ERR, "send replies error: ", err)
        ngx_exit(ERROR)
        return
    end

    local co_updown = thread_spawn(socks_pipe, upsock, downsock)
    local co_downup = thread_spawn(socks_pipe, downsock, upsock)

    ngx.thread.wait(co_updown)
    ngx.thread.wait(co_downup)
end

local _SERVER_MT = {
	run    = _socks5_server_run,
	auth   = _socks5_server_auth
}

local _MT = {
    new = _new_socks5_server
}

local function _new_socks5_server(auth_mth, auth_cb, timeout)
    return setmetatable({
        auth_method = auth_mth,
        auth_cb     = auth_cb,
        timeout     = timeout
    },{ __index = _SERVER_MT})
end

return setmetatable({
        _VERSION    = _VERSION,
    },{ __index = _MT })
