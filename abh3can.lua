-- ABH3 CAN通信 パケット解析プログラム for Wireshark
-- 株式会社ワコー技研 技術部
-- V1.0

-- ID定義
abh3_id = 0
host_id = 0

-- プロトコル定義
local abh3can_proto = Proto("ABH3CAN","ABH3 CAN-Bus Protocol")

-- フィールド定義
abh3can_source_F      = ProtoField.new("SID","abh3can.source",ftypes.UINT8)
abh3can_destination_F = ProtoField.new("DID","abh3can.destination",ftypes.UINT8)
abh3can_pgn_F         = ProtoField.new("PGN","abh3can.pgn",ftypes.STRING)
abh3can_info_F        = ProtoField.new("Data","abh3can.info",ftypes.STRING)

-- フィールド配列
abh3can_proto.fields = {abh3can_source_F, abh3can_destination_F, abh3can_pgn_F, abh3can_info_F}

-- 解析ルーチン
function abh3can_proto.dissector(buffer, pinfo, tree)
    -- プロトコルヘッダ名称
    pinfo.cols.protocol = "ABH3CAN"

    -- ツリー追加
    local subtree = tree:add(abh3can_proto, buffer())
    -- ID追加
    local sid = buffer(16,1):uint()
    subtree:add(abh3can_source_F, sid)
    local did = buffer(17,1):uint()
    subtree:add(abh3can_destination_F, did)
    -- PGN追加
    local exid = bit.band(buffer(16, 4):le_uint() , 0xffffff)
    local pgn  = bit.band(exid , 0xff0000)
    subtree:add(abh3can_pgn_F, string.format("%6X", exid))
    -- パケット毎の情報追加
    if pgn == 0x00ea0000 then -- request
        if abh3_id == did then
            local req_pgn = buffer(24, 3):le_uint()
            local req_group = ((req_pgn % 256) / 8)
            local req_packet = ((req_pgn % 256) % 8)
            local info = string.format("Request PGN: %6X  Group No.: %2d  Packet No.: %1d", req_pgn*256, req_group, req_packet)
            subtree:add(abh3can_info_F, info)
        end
    end
    if pgn == 0x00ef0000 then -- single 0
        if abh3_id == did and host_id == sid then -- HOST -> ABH3
            local velCmdAY = buffer(24, 2):le_int() * 0.2
            local velCmdBX = buffer(26, 2):le_int() * 0.2
            local trqCmdAY = buffer(24, 2):le_int() * 0.01
            local trqCmdBX = buffer(26, 2):le_int() * 0.01
            local input    = buffer(28, 4):le_uint()
            local info = string.format("velCmdAY: %7.1f  velCmdBX: %7.1f  trqCmdAY: %7.2f  trqCmdBX: %7.2f  Input: %8x", velCmdAY, velCmdBX, trqCmdAY, trqCmdBX, input)
            subtree:add(abh3can_info_F, info)
        end
        if abh3_id == sid and host_id == did then -- ABH3 -> HOST
            local velFbkA = buffer(24, 2):le_int() * 0.2
            local velFbkB = buffer(26, 2):le_int() * 0.2
            local velFbkY = buffer(28, 2):le_int() * 0.2
            local velFbkX = buffer(30, 2):le_int() * 0.2
            local info = string.format("velFbkA:  %7.1f  velFbkB:  %7.1f  velFbkY:  %7.1f  velFbkX:  %7.1f", velFbkA, velFbkB, velFbkY, velFbkX)
            subtree:add(abh3can_info_F, info)
        end
    end
    if pgn == 0x00ff0000 then -- broadcast
        if abh3_id == sid then
            -- 共通
            local brd_group = (did / 8)
            local brd_packet = (did % 8)
            local info = string.format("Broadcast Packet     Group No.: %2d  Packet No.: %1d", brd_group, brd_packet)
            -- パケット毎
            if brd_packet == 0 then -- パケット０
                info = info..string.format("  Error   : %08X  Alarm : %08X", buffer(24, 4):le_uint(), buffer(28, 4):le_uint())
            elseif brd_packet == 1 then -- パケット１
                info = info..string.format("  Control : %08X  InOut : %08X", buffer(24, 4):le_uint(), buffer(28, 4):le_uint())
            elseif brd_packet == 2 then -- パケット２
                local velCmdAY = buffer(24, 2):le_int() * 0.2
                local velCmdBX = buffer(26, 2):le_int() * 0.2
                local velFbkAY = buffer(28, 2):le_int() * 0.2
                local velFbkBX = buffer(30, 2):le_int() * 0.2
                info = info..string.format("  velCmdAY : %7.1f  velCmdBX : %7.1f  velFbkAY : %7.1f  velFbkBX : %7.1f", velCmdAY, velCmdBX, velFbkAY, velFbkBX)
            elseif brd_packet == 3 then -- パケット３
                local trqCmdAY = buffer(24, 2):le_int() * 0.01
                local trqCmdBX = buffer(26, 2):le_int() * 0.01
                local loadA = buffer(28, 2):le_int()
                local loadB = buffer(30, 2):le_int()
                info = info..string.format("  trqCmdAY : %7.2f  trqCmdBX : %7.2f  LoadA : %3d  loadB : %3d", trqCmdAY, trqCmdBX, loadA, loadB)
            elseif brd_packet == 4 then -- パケット４
                info = info..string.format("  pulseA : %11d  pulseB : %11d", buffer(24, 4):le_int(), buffer(28, 4):le_int())
            elseif brd_packet == 5 then -- パケット５
                local analog0  = buffer(24, 2):le_int() * 0.01
                local analog1  = buffer(26, 2):le_int() * 0.01
                local mainV    = buffer(28, 2):le_int() * 0.1
                local controlV = buffer(30, 2):le_int() * 0.1
                info = info..string.format("  analog0 : %7.2f  analog1 : %7.2f  MainVolt : %7.1f  ControlVolt : %7.1f", analog0, analog1, mainV, controlV)
            elseif brd_packet == 6 then -- パケット６
                local monitor0  = buffer(24, 4):le_float()
                local monitor1  = buffer(28, 4):le_float()
                info = info..string.format("  monitor0 : %7.4f  monitor1 : %7.4f", monitor0, monitor1)
            end
            subtree:add(abh3can_info_F, info)
        end
    end
end

-- ポストディセクタの設定
register_postdissector(abh3can_proto)

-- ID設定ダイアログ
local function abh3can_dialog_menu()
    local function abh3can_dialog_func(abh3ID,hostID)
    abh3_id = tonumber(abh3ID)
    host_id = tonumber(hostID)
    end

    new_dialog("ABH3CAN ID Setting Dialog",abh3can_dialog_func,"ABH3 ID","HOST ID")
end

-- メニュー登録
register_menu("ABH3CAN ID Setting",abh3can_dialog_menu,MENU_TOOLS_UNSORTED)
