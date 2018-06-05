----------------------------------------
-- script-name: nvmetcp.lua
--
-- author: Nikolay Assa <Nikolay.Assa@cavium.com>
-- Copyright (C) 2018 Cavium, Inc
--
-- Version: 0.3
--
-------------------------------------------------------------------------------
--[[

  Plugin for Wireshark to dissect NVMe over TCP fabrics PDUs
  Aligned to headers in include/linux/nvme-tcp.h as of Feb 15, 2018
  from git@gitlab.com:nvme-over-fabrics/linux.git

]]-----------------------------------------------------------------------------

-- default settings - can be changed by GUI
local default_settings =
{
    debug_en  = false,
    enabled   = true, -- whether this dissector is enabled or not
    port      = 4420, -- default TCP port number for NVMe/TCP
}

local dprint = function() end

local function apply_debug_enable()
  if default_settings.debug_en == true then
    dprint = function(...)
      print(table.concat({"Lua:", ...}," "))
    end
  else
    dprint = function() end
  end
end
-- call it now
apply_debug_enable()

local nvmetcp_proto = Proto("NVMeTCP", "NVMe over TCP")
dprint("NVMeTCP Protocol registered")

--enum nvme_tcp_pdu_opcode {
--  nvme_tcp_connect      = 0x0,
--  nvme_tcp_connect_rep  = 0x1,
--  nvme_tcp_cmd          = 0x2,
--  nvme_tcp_comp         = 0x3,
--  nvme_tcp_r2t          = 0x4,
--  nvme_tcp_data_h2c     = 0x5,
--  nvme_tcp_data_c2h     = 0x6,
--};

local pdutype = {
    ICReq       = 0,
    ICResp      = 1,
    CapsuleCmd  = 2,
    CapsuleResp = 3,
    R2T         = 4,
    H2CData     = 5,
    C2HData     = 6,
}

-------------------------------------------------------------------------------
-- a function to convert tables of enumerated types to value-string tables
-- i.e., from { "name" = number } to { number = "name" }
--
local function makeValString(enumTable)
  local t = {}
  for name,num in pairs(enumTable) do
    t[num] = name
  end
  return t
end

local pdutype_str = makeValString(pdutype)

-- common PDU Header (CH) fields
--/**
-- * struct nvme_tcp_hdr - nvme tcp generic header
-- *
-- * @opcode:        pdu opcode
-- * @flags:         pdu flags
-- * @pdgst:         pdu digest (optional, reserved otherwise)
-- * @length:        wire byte-length of pdu
-- */
--struct nvme_tcp_hdr {
--  __u8    opcode;
--  __u8    flags;
--  __le16  pdgst;
--  __le32  length;
--} __packed;

local ch = {
  opcode  = ProtoField.uint8("nvmetcp.opcode", "Opcode", base.HEX, pdutype_str),
  flags   = ProtoField.uint8("nvmetcp.flags", "flags", base.HEX),
  pdgst   = ProtoField.uint16("nvmetcp.pdgst", "PDU digest", base.DEC),
  length  = ProtoField.uint32("nvmetcp.length", "PDU Length", base.DEC),
  
  -----------------------------------------------------------------------------
  -- bits in flags are shown separately
  --  
  flag_hdgst    = ProtoField.bool("nvmetcp.flags.hdgstf", "Header digest valid", 8, nil, 0x1),
  flag_ddgst    = ProtoField.bool("nvmetcp.flags.ddgstf", "Data digest valid", 8, nil, 0x2),
  flag_last     = ProtoField.bool("nvmetcp.flags.last", "Last PDU in transfer", 8, nil, 0x4),
  flag_success  = ProtoField.bool("nvmetcp.flags.success", "Command completed", 8, nil, 0x8),
  flag_rsvd     = ProtoField.uint8("nvmetcp.flags.reserved", "Reserved", base.DEC, nil, 0xF0)
}

-- Specific PDU Header (PSH) fields

-- ICReq
--/**
-- * struct nvme_tcp_init_conn_req_pdu - nvme tcp connect request
-- *
-- * @hdr:           nvme-tcp generic header
-- * @recfmt:        format of the connect request data
-- * @maxr2t:        maximum r2ts per request supported
-- * @c2hdoff:       host data offset for c2h data pdu
-- * @digest:        digest types enabled
-- */
--struct nvme_tcp_init_conn_req_pdu {
--    struct nvme_tcp_hdr   hdr;
--    __le16        recfmt;
--    __u16         rsvd1;
--    __le32        maxr2t;
--    __le16        c2hdoff;
--    __le16        digest;
--    _u8           rsvd2[108];
--} __packed;

local icreq = {
  pfv     = ProtoField.uint16("nvmetcp.icreq_pfv", "PDU Format Version", base.HEX),
  rsvd1   = ProtoField.uint16("nvmetcp.icreq_rsvd1", "Reserved", base.DEC),
  maxr2t  = ProtoField.uint32("nvmetcp.icreq_maxr2t", "Max Outstanding R2T", base.DEC),
  hpda    = ProtoField.uint16("nvmetcp.icreq_hpda", "Host PDU Data Alignemnt", base.DEC),
  dgst    = ProtoField.uint16("nvmetcp.icreq_dgst", "Host PDU digest enable", base.HEX),
  rsvd2   = ProtoField.new("Reserved", "nvmetcp.icreq_rsvd2", ftypes.NONE),
  
  -----------------------------------------------------------------------------
  -- bits in flags are shown separately
  --  
  hdgst_en  = ProtoField.bool("nvmetcp.icreg_dgst.hdgst_en", "Header digest", 16, nil, 0x1),
  ddgst_en  = ProtoField.bool("nvmetcp.icreg_dgst.ddgst_en", "Data digest", 16, nil, 0x2),
  dgst_rsvd = ProtoField.uint16("nvmetcp.icreg_dgst.reserved", "Reserved", base.DEC, nil, 0xFFFC)
}

-- ICResp
--/**
-- * struct nvme_tcp_init_conn_rep_pdu - nvme tcp connect reply
-- *
-- * @hdr:           nvme-tcp generic header
-- * @recfmt:        format of the connect reply data
-- * @sts:           error status for the associated connect request
-- * @maxdata:       maximum data capsules per r2t supported
-- * @digest:        digest types enabled
-- * @h2cdoff:       controller data offset for h2c data pdu
-- */
--struct nvme_tcp_init_conn_rep_pdu {
--    struct nvme_tcp_hdr  hdr;
--    __le16            recfmt;
--    __le16            sts;
--    __le32            maxdata;
--    __le16            h2cdoff;
--    __le16            digest;
--    __u8              rsvd[108];
--} __packed;

local sts_codes = {
        [0] = "Initialization Successful",
        [1] = "Invalid DIGEST sent in ICReq",
        [2] = "Invalid LENGTH sent in ICReq",
        [3] = "Invalid RECFMT sent in ICReq",
        [4] = "Invalid HPDA sent in ICReq"
}

local icresp = {
  pfv      = ProtoField.uint16("nvmetcp.icresp_pfv", "PDU Format Version", base.HEX),
  sts      = ProtoField.uint16("nvmetcp.icresp_sts", "Status of Request", base.HEX, sts_codes),
  maxdata  = ProtoField.uint32("nvmetcp.icresp_maxdata", "Maximum Data per R2T (or PDU?)", base.DEC),
  cpda     = ProtoField.uint16("nvmetcp.icresp_cpda", "Controler PDU Data Alignment", base.DEC),
  dgst     = ProtoField.uint16("nvmetcp.icresp_dgst", "Controler PDU Header, Data digest", base.HEX),
  rsvd     = ProtoField.new("Reserved", "nvmetcp.icresp_rsvd", ftypes.NONE),

  -----------------------------------------------------------------------------
  -- bits in flags are shown separately
  --
  hdgst_en  = ProtoField.bool("nvmetcp.icresp_dgst.hdgst_en", "Header digest", 16, nil, 0x1),
  ddgst_en  = ProtoField.bool("nvmetcp.icresp_dgst.ddgst_en", "Data digest", 16, nil, 0x2),
  dgst_rsvd = ProtoField.uint16("nvmetcp.icresp_dgst.reserved", "Reserved", base.DEC, nil, 0xFFFC)
}

-- CapsuleCmd
--/**
-- * struct nvme_tcp_cmd_pdu - nvme tcp command
-- *
-- * @hdr:           nvme-tcp generic header
-- * @cmd:           nvme command
-- */
--struct nvme_tcp_cmd_pdu {
--  struct nvme_tcp_hdr	hdr;
--  struct nvme_command	cmd;
--} __packed;

local cmd = {
  cmd         = ProtoField.new("Command SQE", "nvmetcp.cmd", ftypes.NONE),
  in_capsule  = ProtoField.new("In-Capsule Data", "nvmetcp.in_capsule", ftypes.NONE)
}

-- CapsuleResp
--/**
-- * struct nvme_tcp_comp_pdu - nvme tcp completion
-- *
-- * @hdr:           nvme-tcp generic header
-- * @cqe:           nvme completion queue entry
-- */
--struct nvme_tcp_comp_pdu {
--  struct nvme_tcp_hdr	hdr;
--  struct nvme_completion	cqe;
--} __packed;

local cqe = ProtoField.new("Response CQE", "nvmetcp.cqe", ftypes.NONE)

-- R2T
--/**
-- * struct nvme_tcp_r2t_pdu - nvme tcp ready-to-receive
-- *
-- * @hdr:           nvme-tcp generic header
-- * @command_id:    nvme command identifier which this relates to
-- * @ttag:          transfer tag (controller generated)
-- * @r2t_offset:    offset from the start of the command data
-- * @r2t_length:    length in bytes the host is allowed to send
-- */
--struct nvme_tcp_r2t_pdu {
--    struct nvme_tcp_hdr    hdr;
--    __u16             command_id;
--    __u16             ttag;
--    __le32            r2t_offset;
--    __le32            r2t_length;
--    __u8              rsvd[4];
--} __packed;

local r2t = {
  cccid = ProtoField.uint16("nvmetcp.r2t_cccid", "Command Capsule CID (CCCID)", base.HEX),
  ttag  = ProtoField.uint16("nvmetcp.r2t_ttag", "Transfer Tag (TTAG)", base.HEX),
  r2to  = ProtoField.uint32("nvmetcp.r2to", "Requested Data Offset (R2TO)", base.DEC),
  r2tl  = ProtoField.uint32("nvmetcp.r2tl", "Requested Data Length (R2TL)", base.DEC),
  rsvd  = ProtoField.uint32("nvmetcp.r2t_rsvd", "Reserved", base.DEC)
}

-- H2CData, C2HData
--/**
-- * struct nvme_tcp_data_pdu - nvme tcp data unit
-- *
-- * @hdr:           nvme-tcp generic header
-- * @command_id:    nvme command identifier which this relates to
-- * @ttag:          transfer tag (controller generated)
-- * @data_offset:   offset from the start of the command data
-- * @data_length:   length in bytes of the data stream
-- */
--truct nvme_tcp_data_pdu {
--    struct nvme_tcp_hdr    hdr;
--    __u16	            command_id;
--    __u16	            ttag;
--    __le32            data_offset;
--    __le32            data_length;
--    __u8              rsvd[4];
-- __packed;

local data = {
  cccid = ProtoField.uint16("nvmetcp.cccid", "Command Capsule CID (CCCID)", base.HEX),
  ttag  = ProtoField.uint16("nvmetcp.ttag", "Transfer Tag (TTAG)", base.HEX),
  datao = ProtoField.uint32("nvmetcp.datao", "Data Offset", base.DEC),
  datal = ProtoField.uint32("nvmetcp.datal", "Data Length", base.DEC),
  rsvd  = ProtoField.uint32("nvmetcp.rsvd", "Reserved", base.DEC),
  data  = ProtoField.new("Data", "nvmetcp.data", ftypes.NONE)
}

-- all fields
nvmetcp_proto.fields = {
  ch.opcode, ch.flags, ch.pdgst, ch.length, -- CH
  ch.flag_hdgst, ch.flag_ddgst, ch.flag_last, ch.flag_success, ch.flag_rsvd, -- CH flags
  icreq.pfv, icreq.rsvd1, icreq.maxr2t, icreq.hpda, icreq.dgst, icreq.rsvd2, -- PSH ICReq
  icreq.hdgst_en, icreq.ddgst_en, icreq.dgst_rsvd, -- PSH ICReq flags
  icresp.pfv, icresp.sts, icresp.maxdata, icresp.cpda, icresp.dgst, icresp.rsvd, --PSH ICResp
  icresp.hdgst_en, icresp.ddgst_en, icresp.dgst_rsvd, -- PCH ICResp flags
  cmd.cmd, cmd.in_capsule, cqe, -- PSH CapsuleCmd, CapsuleResp
  r2t.cccid, r2t.ttag, r2t.r2to, r2t.r2tl, r2t.rsvd, --PSH R2T
  data.cccid, data.ttag, data.datao, data.datal, data.rsvd, data.data -- PSH H2CData, C2HData
}

-------------------------------------------------------------------------------
-- constants and forward "declarations" of helper functions
--
local NVM_TCP_CMN_HDR_LEN = 8
local dissect_nvme_tcp, check_nvme_tcp_len

-------------------------------------------------------------------------------
-- protocol dissector callback dunciton
--
function nvmetcp_proto.dissector(buffer, pinfo, tree)

  local buffer_len = buffer:len()
  if buffer_len == 0 then return end

  local bytes_consumed = 0

  while bytes_consumed < buffer_len do

    local bytes_processed = dissect_nvme_tcp(buffer, pinfo, tree, bytes_consumed)
    
    if bytes_processed > 0 then
      -- we successfully processed PDU
      bytes_consumed = bytes_consumed + bytes_processed
    elseif bytes_processed == 0 then
      -- error - no dissection took place
      return 0
    else
      -- more bytes needed
      pinfo.desegment_offset = bytes_consumed
      pinfo.desegment_len = -bytes_processed
      
      -- all packet bytes are for this dissector, but more needed
      return buffer_len
    end
  end

  return bytes_consumed

end

-------------------------------------------------------------------------------
-- Determine the length of PDU if possible
--
function check_nvme_tcp_len(buffer, offset)

  -- number of available bytes remaining in buffer 
  local msglen = buffer:len() - offset

  if msglen < NVM_TCP_CMN_HDR_LEN then
    -- nothing dissected - tell main dissector more bytes are needed
    return -DESEGMENT_ONE_MORE_SEGMENT
  end

  -- enough bytes to tell at least the PDU size
  
  -- get the length as an little-endian unsigned integer from header
  local pdu_len = buffer(offset + 4, 4):le_uint()

  if msglen < pdu_len then
    -- we need more bytes to get the whole FPM message
    return -(pdu_len - msglen)
  end

  return pdu_len
end

-------------------------------------------------------------------------------
-- Signle PDU dissector helper function
--
function dissect_nvme_tcp(buffer, pinfo, tree, offset)

  local pdu_len = check_nvme_tcp_len(buffer, offset)
  if pdu_len <= 0 then
    return pdu_len
  end
  
  -- if we got here, then we have a whole PDU in buffer
  local pdu_buf = buffer:range(offset)
  
  local pdu_type = pdu_buf(0,1):le_uint()
  local pdu_name = pdutype_str[pdu_type]

  local subtree = tree:add(nvmetcp_proto, pdu_buf(0,pdu_len), "NVMe/TCP (" .. pdu_name .. ")")
  
  -- dissect common PDU Header (CH)
  subtree:add_le(ch.opcode, pdu_buf(0,1))

  -- sub-tree for flags
  local flagrange = pdu_buf:range(1,1)
  local flag_tree = subtree:add(ch.flags, flagrange)
    flag_tree:add(ch.flag_rsvd, flagrange)
    flag_tree:add(ch.flag_success, flagrange)
    flag_tree:add(ch.flag_last, flagrange)
    flag_tree:add(ch.flag_ddgst, flagrange)
    flag_tree:add(ch.flag_hdgst, flagrange)

  subtree:add_le(ch.pdgst,  pdu_buf(2,2))
  subtree:add_le(ch.length, pdu_buf(4,4))
  
  -- Handle protocol and Info columns
  pinfo.cols.protocol = nvmetcp_proto.name
  pinfo.cols.info:set(pdu_name)
  
  -- dissect specific headers

  if pdu_name == "ICReq" then

    subtree:add_le(icreq.pfv, pdu_buf(8,2))
    subtree:add_le(icreq.rsvd1, pdu_buf(10,2))
    subtree:add_le(icreq.maxr2t, pdu_buf(12,4))
    subtree:add_le(icreq.hpda, pdu_buf(16,2))
    
    local dgst_range = pdu_buf:range(18,2)
    local dgst_tree = subtree:add(icreq.dgst, dgst_range)
      dgst_tree:add(icreq.dgst_rsvd, dgst_range)
      dgst_tree:add(icreq.ddgst_en, dgst_range)
      dgst_tree:add(icreq.hdgst_en, dgst_range)
    
    subtree:add_le(icreq.rsvd2, pdu_buf(20,108)):append_text(" (108 bytes)")

  elseif pdu_name == "ICResp" then

    subtree:add_le(icresp.pfv, pdu_buf(8,2))
    subtree:add_le(icresp.sts, pdu_buf(10,2))
    subtree:add_le(icresp.maxdata, pdu_buf(12,4))
    subtree:add_le(icresp.cpda, pdu_buf(16,2))
    
    local dgst_range = pdu_buf:range(18,2)
    local dgst_tree = subtree:add(icresp.dgst, dgst_range)
      dgst_tree:add(icresp.dgst_rsvd, dgst_range)
      dgst_tree:add(icresp.ddgst_en, dgst_range)
      dgst_tree:add(icresp.hdgst_en, dgst_range)

    subtree:add_le(icresp.rsvd, pdu_buf(20,108)):append_text(" (108 bytes)")

    -- append to Info column
    local sts_bits = pdu_buf(10,2):le_uint()
    pinfo.cols.info:append(" (" .. sts_codes[sts_bits] ..")" )

  elseif pdu_name == "CapsuleCmd" then

    subtree:add_le(cmd.cmd, pdu_buf(8,64)):append_text(" (64 bytes)")

    in_capsule_len = pdu_len - (8 + 64)
    if (in_capsule_len > 0) then
      subtree:add_le(cmd.in_capsule, pdu_buf(8+64,in_capsule_len)):append_text(" (" .. in_capsule_len .." bytes)")
    end

  elseif pdu_name == "CapsuleResp" then

    subtree:add_le(cqe, pdu_buf(8,16)):append_text(" (16 bytes)")

  elseif pdu_name == "R2T" then

    subtree:add_le(r2t.cccid, pdu_buf(8,2))
    subtree:add_le(r2t.ttag, pdu_buf(10,2))
    subtree:add_le(r2t.r2to, pdu_buf(12,4))
    subtree:add_le(r2t.r2tl, pdu_buf(16,4))
    subtree:add_le(r2t.rsvd, pdu_buf(20,4))

    local cccid = string.format("0x%04x", pdu_buf(8,2):le_uint())
    local ttag = string.format("0x%04x", pdu_buf(10,2):le_uint())
    pinfo.cols.info:append(" (CCCID:" .. cccid .."; TTAG:" .. ttag ..")" )

  elseif pdu_name == "H2CData" or pdu_name == "C2HData" then

    subtree:add_le(data.cccid, pdu_buf(8,2))
    subtree:add_le(data.ttag, pdu_buf(10,2))
    subtree:add_le(data.datao, pdu_buf(12,4))
    subtree:add_le(data.datal, pdu_buf(16,4))
    subtree:add_le(data.rsvd, pdu_buf(20,4))
    
    local data_len = pdu_len - 24
    if (data_len > 0) then
      subtree:add_le(data.data, pdu_buf(24,data_len)):append_text(" (" .. data_len .." bytes)")
    end

    local cccid = string.format("0x%04x", pdu_buf(8,2):le_uint())
    local ttag = string.format("0x%04x", pdu_buf(10,2):le_uint())
    pinfo.cols.info:append(" (CCCID:" .. cccid .. "; TTAG:" .. ttag ..") ")

  end
  
  return pdu_len
  
end

--------------------------------------------------------------------------------
-- Protocol dissection invoked for a specific TCP port,
-- by adding such port to the TCP dissector table
local function enable_dissector()
    DissectorTable.get("tcp.port"):add(default_settings.port, nvmetcp_proto)
end
-- call it now - enabled by default
enable_dissector()

local function disable_dissector()
    DissectorTable.get("tcp.port"):remove(default_settings.port, nvmetcp_proto)
end

-------------------------------------------------------------------------------
-- register our preferences
nvmetcp_proto.prefs.enabled  = Pref.bool("Dissector enabled", default_settings.enabled,
                                          "Whether the NVMe/TCP dissector is enabled or not")
nvmetcp_proto.prefs.debug_en = Pref.bool("Debug", default_settings.debug_en,
                                          "Whether debug prints are enabled")
nvmetcp_proto.prefs.port     = Pref.uint("Port number", default_settings.port,
                                          "The TCP port number for NVMe/TCP")
----------------------------------------
-- the function for handling preferences being changed
function nvmetcp_proto.prefs_changed()
    dprint("prefs_changed called")

    default_settings.debug_en = nvmetcp_proto.prefs.debug_en
    apply_debug_enable()

    if default_settings.enabled ~= nvmetcp_proto.prefs.enabled then
        default_settings.enabled = nvmetcp_proto.prefs.enabled
        if default_settings.enabled then
            enable_dissector()
        else
            disable_dissector()
        end
        -- have to reload the capture file for this type of change
        reload()
    end
    
    if default_settings.port ~= nvmetcp_proto.prefs.port then
        -- remove old one, if not 0
        if default_settings.port ~= 0 then
            DissectorTable.get("tcp.port"):remove(default_settings.port, nvmetcp_proto)
        end
        -- set our new default
        default_settings.port = nvmetcp_proto.prefs.port
        -- add new one, if not 0
        if default_settings.port ~= 0 then
            DissectorTable.get("tcp.port"):add(default_settings.port, nvmetcp_proto)
        end
    end

end