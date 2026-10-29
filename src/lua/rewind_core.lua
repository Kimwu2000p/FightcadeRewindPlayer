-- ============================================================================
-- FightcadeRewindPlayer v1.1 - rewind_core.lua 核心引擎 (黃金同步與 64 槽位安全極速版)
-- 關鍵修正：
-- 1. 嚴格限制記憶體快照槽位在 Slot 1..42 (徹底避開 FBNeo save_mem 模數 64 回繞覆寫 Slot 1 的 Bug)
-- 2. 開局錨點 Slot 1 (0 vs 0) 具備記憶體槽位 + 實體檔案 (anchor_0v0.fs) 雙重雜湊校驗保護
-- 3. 統一於 emu.registerafter 原子化執行「設播放頭 (delta=0) -> 載入快照 -> 存檔」，100% 消除 1 幀相位偏移
-- ============================================================================

local MAX_CAPACITY_FRAMES  = 540000  -- 150 分鐘最大容量 (9000 秒 * 60 FPS)
local DEFAULT_SCALE_FRAMES = 54000   -- 預設全域時間軸底限：15 分鐘 (900 秒)

-- 【鐵律】：FBNeo save_mem 底層槽位上限為 64 (超過 64 會發生 % 64 回繞覆寫 Slot 1)！
-- 因此總槽位嚴格控制在 42 格以內：
local ANCHOR_SLOT      = 1     -- 永久鎖死開局錨點 (第 30 幀 0 vs 0，絕不覆寫)
local GLOBAL_MIN_SLOT  = 2     -- 全局動態抽稀池起點 (共 32 格：Slot 2..33)
local GLOBAL_MAX_SLOT  = 33
local LOCAL_MIN_SLOT   = 34    -- 貼身環狀護衛池起點 (共 8 格：Slot 34..41，涵蓋最近 24 秒)
local LOCAL_MAX_SLOT   = 41
local SLOT_PAUSE       = 42    -- 手動暫停與結尾定格專用槽位
local TOTAL_POOL_SLOTS = 42

local BASE_STRIDE      = 180   -- 基礎粒度：每 180 幀 (3 秒) 一格
local global_stride    = BASE_STRIDE
local local_ring_idx   = LOCAL_MIN_SLOT
local anchor_saved     = false

-- 記錄每個 Slot 當前儲存的真實幀號與 RAM 校驗雜湊 (-1 代表空閒)
local slot_frames      = {}
local slot_hashes      = {}
local slot_objs        = {}
local anchor_file_obj  = nil

-- 引擎狀態常數 (與 C# 控制台 100% 統一對齊)
local STATE_PLAYBACK   = 0     -- 0 = 正常 60 FPS 播放
local STATE_PAUSED     = 1     -- 1 = 已手動暫停
local STATE_JIT_SEEK   = 2     -- 2 = Turbo 極速追趕中
local STATE_EOF_FREEZE = 3     -- 3 = 播畢定格 (可隨時自由倒帶)

local engine_state       = STATE_PLAYBACK
local cur_frame          = 0
local max_seen_frame     = 0
local target_frame       = 0
local is_paused          = false
local reached_eof        = false
local pause_after_seek   = false
local eof_grace_frames   = 0     -- 跳轉或撞尾後強制以 normal 速度渲染 2 幀，確保 DirectX 完整刷出畫面
local pending_pct        = nil   -- 記錄尚未見底時點擊的目標百分比，用於撞尾自動回彈 (Snap-Back)
local is_fast_forwarding = false -- 持續快轉旗標
local was_turbo_recording = false -- 極速快錄狀態跟蹤
local last_seen_fc       = -1    -- 單幀防重入保護
local freeze_tick        = 0

-- 動態解析腳本與模擬器目錄
local script_dir = ""
local fbneo_dir  = ""
pcall(function()
    if debug and debug.getinfo then
        local info = debug.getinfo(1, "S")
        if info and info.source then
            local src = info.source:gsub("^@", "")
            local dir = src:match("^(.*[/\\])")
            if dir then
                script_dir = dir
                local parent = dir:match("^(.*[/\\])scripts[/\\]?$")
                if parent then
                    fbneo_dir = parent
                end
            end
        end
    end
end)
if script_dir == "" then script_dir = "scripts\\" end

local ipc_cmd_path    = script_dir .. "ipc_cmd.txt"
local ipc_state_path  = script_dir .. "ipc_state.txt"
local debug_log_path  = script_dir .. "rewind_debug.log"
local anchor_fs_path  = script_dir .. "anchor_0v0.fs"

local function log_msg(msg)
    pcall(function()
        local f = io.open(debug_log_path, "a")
        if f then
            f:write(string.format("[%s] [v1.1] %s\n", os.date("%Y-%m-%d %H:%M:%S"), msg))
            f:close()
        end
    end)
end

pcall(function()
    log_msg("=== FBNEO LUA ENVIRONMENT AUDIT ===")
    if emu then
        for k, v in pairs(emu) do log_msg("EMU_API: " .. tostring(k)) end
    end
    if sound then
        for k, v in pairs(sound) do log_msg("SOUND_API: " .. tostring(k)) end
    end
    if audio then
        for k, v in pairs(audio) do log_msg("AUDIO_API: " .. tostring(k)) end
    end
end)

-- 基板硬體架構自動偵測 (用於計算 Work RAM 校驗雜湊)
local PLATFORM  = "NEOGEO"
local RAM_START = 0x100000
local RAM_END   = 0x10FFFF

pcall(function()
    local active_game = "garou"
    local fg = io.open(script_dir .. "active_game.txt", "r")
    if fg then
        local g_line = fg:read("*l")
        fg:close()
        if g_line and g_line:match("%S+") then
            active_game = g_line:match("%S+"):lower()
        end
    end
    if active_game:find("sfiii") or active_game:find("cps3") or active_game:find("redearth") then
        PLATFORM  = "CPS3"
        RAM_START = 0x06000000
        RAM_END   = 0x0600FFFF
    elseif active_game:find("sf2") or active_game:find("cps1") or active_game:find("sfz") or active_game:find("sfa") or active_game:find("cps2") or active_game:find("dstlk") or active_game:find("vsav") or active_game:find("msh") or active_game:find("xmvsf") or active_game:find("mvsc") then
        PLATFORM  = "CPS1_2"
        RAM_START = 0xFF0000
        RAM_END   = 0xFFFFFF
    else
        PLATFORM  = "NEOGEO"
        RAM_START = 0x100000
        RAM_END   = 0x10FFFF
    end
end)

-- 計算當前 Work RAM 校驗雜湊 (僅於存檔/讀檔瞬間呼叫，驗證快照完整性)
local function ram_hash()
    local h1, h2 = 0, 0
    if memory and memory.readword then
        for a = RAM_START, RAM_END, 16 do
            local w = memory.readword(a)
            h1 = (h1 + w) % 65521
            h2 = (h2 + h1) % 65521
        end
    end
    return h2 * 65536 + h1
end

-- 綁定 ggponet.dll 導出的記憶體 C 函式
local f_get_frame      = nil
local f_set_rewind     = nil
local f_save_inputs    = nil
local f_restore_inputs = nil
local f_poll_cmd       = nil
local f_update_state   = nil
local f_set_paused     = nil
local f_get_scores     = nil
local f_set_scores     = nil
local bound_dll_path   = "NONE"

pcall(function()
    if package and package.loadlib then
        local dll_candidates = {}
        if fbneo_dir ~= "" then
            table.insert(dll_candidates, fbneo_dir .. "ggponet.dll")
        end
        if script_dir ~= "" then
            table.insert(dll_candidates, script_dir .. "..\\ggponet.dll")
        end
        table.insert(dll_candidates, "ggponet.dll")
        table.insert(dll_candidates, "fbneo\\ggponet.dll")
        table.insert(dll_candidates, "emulator\\fbneo\\ggponet.dll")

        for _, dll_p in ipairs(dll_candidates) do
            local g = package.loadlib(dll_p, "lua_get_input_frame")
            if g then
                f_get_frame      = g
                f_set_rewind     = package.loadlib(dll_p, "lua_set_rewind_frame")
                f_set_paused     = package.loadlib(dll_p, "lua_set_paused")
                f_save_inputs    = package.loadlib(dll_p, "lua_snapshot_save_inputs")
                f_restore_inputs = package.loadlib(dll_p, "lua_snapshot_restore_inputs")
                f_poll_cmd       = package.loadlib(dll_p, "lua_poll_gui_cmd")
                f_update_state   = package.loadlib(dll_p, "lua_update_gui_state")
                f_get_scores     = package.loadlib(dll_p, "lua_get_scores")
                f_set_scores     = package.loadlib(dll_p, "lua_set_scores")
                f_set_audio_mute = package.loadlib(dll_p, "lua_set_audio_mute")
                f_is_turbo_rec   = package.loadlib(dll_p, "lua_is_turbo_rec")
                bound_dll_path   = dll_p
                break
            end
        end
    end
end)

log_msg(string.format("啟動完成 | platform=%s | script_dir=%s | bound_dll=%s | get=%s set=%s",
    PLATFORM, script_dir, bound_dll_path, tostring(f_get_frame ~= nil), tostring(f_set_rewind ~= nil)))

-- ============================================================================
-- 原生進程內音效管理 (In-Process Native Audio Manager)
-- 零驅動相依、零跨進程枚舉、零註冊表殘留，極速追趕 (Turbo/Seek/Fast-Forward) 與暫停時
-- 即時跳過 DirectSound/WASAPI 合成，杜絕爆音尖叫，切回 1x 正常播放時即時恢復！
-- ============================================================================
local current_mute_state = -1

local function set_audio_mute(mute)
    if mute ~= current_mute_state then
        current_mute_state = mute
        if f_set_audio_mute then
            pcall(function() f_set_audio_mute(mute) end)
        end
    end
end

-- ============================================================================
-- 比分歷史時間軸管理器 (Score Timeline Manager)
-- 保證跳轉 (Seek/PCT) 時頂部比分板與該幀歷史狀態 100% 同步
-- ============================================================================
local score_timeline = {}
local last_recorded_p1 = -1
local last_recorded_p2 = -1

local function sample_and_record_scores(f_num)
    if not f_get_scores then return end
    local ok, p1, p2 = pcall(f_get_scores)
    if not ok or not p1 or not p2 then return end

    if #score_timeline == 0 or p1 ~= last_recorded_p1 or p2 ~= last_recorded_p2 then
        table.insert(score_timeline, { frame = f_num, p1 = p1, p2 = p2 })
        last_recorded_p1 = p1
        last_recorded_p2 = p2
        log_msg(string.format("SCORE_TIMELINE_RECORD: frame=%d -> %d VS %d (total_pts=%d)", f_num, p1, p2, #score_timeline))
    end
end

local function sync_score_at_frame(f_num)
    if not f_set_scores or #score_timeline == 0 then return end
    local best_p1 = score_timeline[1].p1
    local best_p2 = score_timeline[1].p2
    for i = #score_timeline, 1, -1 do
        if score_timeline[i].frame <= f_num then
            best_p1 = score_timeline[i].p1
            best_p2 = score_timeline[i].p2
            break
        end
    end
    pcall(function() f_set_scores(best_p1, best_p2) end)
    log_msg(string.format("SCORE_TIMELINE_SYNC: frame=%d -> Restored %d VS %d", f_num, best_p1, best_p2))
end

-- 讀取 C 端底層狀態 (play_frame, record_frame, c_eof)
local function read_c_status()
    local c_play = cur_frame
    local c_rec  = max_seen_frame
    local c_eof  = 0
    local c_starving = 0
    local c_ah_level = 8
    if f_get_frame then
        local ok, p, r, e, s, a = pcall(f_get_frame)
        if ok and p then
            c_play = p
            c_rec  = r or max_seen_frame
            c_eof  = e or 0
            c_starving = s or 0
            c_ah_level = a or 8
        end
    end
    if c_rec > max_seen_frame then max_seen_frame = c_rec end
    return c_play, c_rec, c_eof, c_starving, c_ah_level
end

-- 同步狀態至 C 端與 ipc_state.txt (雙通道保底供 GUI 即時讀取)
local function sync_gui_state(force_disk_flush)
    local c_play, c_rec, c_eof = read_c_status()
    local total_f = math.max(max_seen_frame, c_rec or 0)
    local is_eof_unlocked = (reached_eof or (c_eof == 1)) and 1 or 0

    local st_code = STATE_PLAYBACK
    if reached_eof and is_paused then
        st_code = STATE_EOF_FREEZE -- 3
    elseif is_paused then
        st_code = STATE_PAUSED     -- 1
    elseif engine_state == STATE_JIT_SEEK or is_fast_forwarding then
        st_code = STATE_JIT_SEEK   -- 2 (快轉中，絕不誤報為 3 EOF！)
    end

    -- 原生進程內音效管理：僅在 normal 1x 播放 (st_code == STATE_PLAYBACK) 時發聲，
    -- 在 Turbo/Seek、Fast Forward、Pause 或定格時，進程內即時跳過音效合成！
    local should_mute = (st_code ~= STATE_PLAYBACK) and 1 or 0
    set_audio_mute(should_mute)

    if f_update_state then
        local scr_w = (emu.screenwidth and emu.screenwidth()) or 0
        local scr_h = (emu.screenheight and emu.screenheight()) or 0
        local fl_flag = force_disk_flush and 1 or 0
        pcall(function()
            f_update_state(cur_frame, total_f, is_eof_unlocked, st_code, target_frame, scr_w, scr_h, fl_flag)
        end)
    else
        -- 僅在 C 端 f_update_state 未綁定時，由 Lua 備援寫入 ipc_state.txt
        local is_probing = (engine_state == STATE_JIT_SEEK or is_fast_forwarding)
        local need_write_disk = force_disk_flush or (not is_probing) or (cur_frame % 240 == 0)
        if need_write_disk then
            pcall(function()
                local f = io.open(ipc_state_path, "w")
                if f then
                    f:write(string.format("%d %d %d %d %d\n",
                        cur_frame, total_f, is_eof_unlocked, st_code, target_frame))
                    f:close()
                end
            end)
        end
    end
end

-- ============================================================================
-- 1. 快照底層相容封裝 (Slot 1..42 安全範圍 + 開局錨點雙重實體備份)
-- ============================================================================
local function init_snapshot_pool()
    for s = 1, TOTAL_POOL_SLOTS do
        slot_frames[s] = -1
        slot_hashes[s] = 0
        if savestate and savestate.create then
            pcall(function() slot_objs[s] = savestate.create(s) end)
        end
    end
    if savestate and savestate.create then
        pcall(function() anchor_file_obj = savestate.create(anchor_fs_path) end)
    end
    global_stride  = BASE_STRIDE
    local_ring_idx = LOCAL_MIN_SLOT
    anchor_saved   = false
end

local function raw_save_slot(slot)
    local ok, err = false, nil
    if savestate and savestate.save_mem then
        ok, err = pcall(function() savestate.save_mem(slot) end)
    elseif savestate and savestate.save and slot_objs[slot] then
        ok, err = pcall(function() savestate.save(slot_objs[slot]) end)
    end
    if ok then
        -- 【RAM Hash 旁路優化】：
        -- 開局錨點 (Slot 1) 永遠執行完整雙字節 Adler32 雜湊保護；
        -- 僅在探底狂奔期間 (JIT_SEEK / FFWD) 暫停其他槽位的 Work RAM 雜湊運算，立省每秒 14 次 CPU 迴圈！
        local is_probing = (engine_state == STATE_JIT_SEEK or is_fast_forwarding)
        if slot == ANCHOR_SLOT or not is_probing then
            slot_hashes[slot] = ram_hash(slot == ANCHOR_SLOT)
        else
            slot_hashes[slot] = 0
        end

        if slot == ANCHOR_SLOT and savestate and savestate.save and anchor_file_obj then
            pcall(function() savestate.save(anchor_file_obj) end)
        end
        if f_save_inputs then
            pcall(function() f_save_inputs(slot) end)
        end
    end
    return ok, err
end

local function raw_load_slot(slot)
    local before_h = ram_hash(slot == ANCHOR_SLOT)
    local ok, err = false, nil

    -- 若載入開局錨點 Slot 1，先載入記憶體槽位並核驗 Hash；若受損則立即由獨立檔案快照救援
    if savestate and savestate.load_mem then
        ok, err = pcall(function() savestate.load_mem(slot) end)
    elseif savestate and savestate.load and slot_objs[slot] then
        ok, err = pcall(function() savestate.load(slot_objs[slot]) end)
    end

    local after_h = ram_hash()
    local expected_h = slot_hashes[slot] or 0

    if slot == ANCHOR_SLOT and anchor_file_obj and savestate and savestate.load then
        if (not ok) or (expected_h ~= 0 and after_h ~= expected_h) then
            local ok_f, err_f = pcall(function() savestate.load(anchor_file_obj) end)
            if ok_f then
                ok = true
                after_h = ram_hash()
                log_msg(string.format("ANCHOR_FILE_RESCUE: 由獨立檔案 anchor_0v0.fs 成功還原 0v0 初始狀態！hash=%08x", after_h))
            else
                err = err_f
            end
        end
    end

    if ok and f_restore_inputs then
        pcall(function() f_restore_inputs(slot) end)
    end

    if slot ~= SLOT_PAUSE then
        local match_str = (expected_h == 0 or after_h == expected_h) and "YES" or "NO"
        log_msg(string.format("[LOADCHK] slot=%d snap_f=%d before=%08x after=%08x saved=%08x match=%s",
            slot, slot_frames[slot] or -1, before_h, after_h, expected_h, match_str))
    end

    return ok, err
end

-- ============================================================================
-- 2. 輕量化智慧快照寫入器 (Slot 2..33 全局骨幹池 + Slot 34..41 貼身微調池)
-- ============================================================================
local function acquire_global_slot()
    for s = GLOBAL_MIN_SLOT, GLOBAL_MAX_SLOT do
        if slot_frames[s] == -1 then return s end
    end

    -- 滿池對半抽稀 (Decimation)：步幅乘 2 (180 -> 360 -> 720 -> 1440)
    global_stride = global_stride * 2
    local freed_slot = nil
    for s = GLOBAL_MIN_SLOT, GLOBAL_MAX_SLOT do
        local f = slot_frames[s]
        if f > 0 and (f % global_stride ~= 0) then
            slot_frames[s] = -1 -- 釋放奇數倍位置供後續時間軸使用
            slot_hashes[s] = 0
            if not freed_slot then freed_slot = s end
        end
    end
    log_msg(string.format("GLOBAL_POOL_DECIMATED: new_stride=%d (%ds)", global_stride, math.floor(global_stride / 60)))
    return freed_slot or GLOBAL_MIN_SLOT
end

local function record_snapshot_at_frame(f_num, c_rec_in, c_eof_in)
    if f_num <= 0 then return end

    -- 【防污染鐵閘】：歷史回放期間 (cur_frame < max_seen_frame) 絕對禁止寫入快照！
    if cur_frame < max_seen_frame then return end

    -- A. 開局第 1 個不死錨點 (Slot 1，設在第 30 幀確保遊戲已穩定初始化為 0 vs 0)
    if not anchor_saved and f_num >= 30 then
        if raw_save_slot(ANCHOR_SLOT) then
            slot_frames[ANCHOR_SLOT] = f_num
            anchor_saved = true
            log_msg(string.format("ANCHOR_SLOT_1_SAVED: frame=%d hash=%08x", f_num, slot_hashes[ANCHOR_SLOT] or 0))
        end
        return
    end

    -- 【極速短路】：所有快照步幅 (60/180/360) 皆為 60 之倍數，非 60 倍數幀 0 成本直接返回！
    if f_num % 60 ~= 0 then return end

    -- B. 探底階段自適應步幅 (Adaptive Striding)
    local is_probing = (engine_state == STATE_JIT_SEEK or is_fast_forwarding)
    local effective_base_stride = BASE_STRIDE -- 預設 180 (3 秒)
    
    if is_probing then
        local c_rec = c_rec_in or max_seen_frame
        local c_eof = c_eof_in or 0
        local distance_to_eof = (c_eof == 1 and c_rec > 100) and (c_rec - f_num) or 99999
        if distance_to_eof <= 300 then
            -- 決勝衝刺圈 (最後 5 秒)：步幅縮小至 60 幀 (1 秒)，確保結尾 K.O. 畫面精度
            effective_base_stride = 60
        else
            -- 狂奔階段：步幅放寬至 360 幀 (6 秒)，減少 50% 快照寫入負擔
            effective_base_stride = 360
        end
    end

    if f_num % effective_base_stride ~= 0 then return end

    -- 若該幀已存在於槽位中，跳過不重複存
    for s = 1, LOCAL_MAX_SLOT do
        if slot_frames[s] == f_num then return end
    end

    -- C. 若符合全局骨幹池步幅 (global_stride)，存入全局池 (Slot 2..33)
    if f_num % global_stride == 0 then
        local g_slot = acquire_global_slot()
        if raw_save_slot(g_slot) then
            slot_frames[g_slot] = f_num
        end
    else
        -- D. 存入貼身微調池 (Slot 34..41，8 格保持最近 24 秒每 3 秒一格)
        local l_slot = local_ring_idx
        local_ring_idx = local_ring_idx + 1
        if local_ring_idx > LOCAL_MAX_SLOT then local_ring_idx = LOCAL_MIN_SLOT end

        if raw_save_slot(l_slot) then
            slot_frames[l_slot] = f_num
        end
    end
end

-- 搜尋「開局錨點 + 全局骨幹池 + 貼身環狀池」，找出 <= target_f 且 <= max_seen_frame 的最接近快照
local function find_best_snapshot(target_f)
    local best_s = nil
    local best_f = -1

    for s = 1, LOCAL_MAX_SLOT do
        local sf = slot_frames[s]
        if sf ~= -1 and sf <= target_f and sf <= max_seen_frame and sf > best_f then
            best_f = sf
            best_s = s
        end
    end

    -- 保底機制：若目標幀比所有快照還早，強制回傳開局錨點 Slot 1
    if not best_s and slot_frames[ANCHOR_SLOT] ~= -1 then
        best_s = ANCHOR_SLOT
        best_f = slot_frames[ANCHOR_SLOT]
    end

    return best_f, best_s
end

-- ============================================================================
-- 3. 零失誤隨意跳轉引擎 (嚴格對齊黃金基準版：registerafter 內先設 delta=0 再 load)
-- ============================================================================
local function seek_to_frame(dest_frame, keep_paused, is_pct_jump)
    local c_play, c_rec, c_eof = read_c_status()

    if c_eof == 1 and c_rec > 100 and dest_frame >= c_rec - 5 then
        dest_frame = c_rec - 5
    end
    if dest_frame < 0 then dest_frame = 0 end
    if dest_frame > MAX_CAPACITY_FRAMES then dest_frame = MAX_CAPACITY_FRAMES end

    -- 記錄進入前是否處於暫停狀態 (用於消除暫停期間 68000 CPU 偷跑 1 幀造成的 1-Frame Desync)
    local was_paused   = is_paused
    reached_eof        = false
    is_paused          = false
    pause_after_seek   = false
    is_fast_forwarding = false
    eof_grace_frames   = 0
    freeze_tick        = 0
    last_seen_fc       = -1 -- DEADLOCK_FIX: 重設幀計數防止主循環短路攔截
    pcall(function() emu.speedmode("normal") end)
    if f_set_paused then pcall(function() f_set_paused(0) end) end

    -- 分支 A: 回到開局 (dest_frame <= 60) -> 直接載入 Slot 1 錨點 (0 vs 0)
    if dest_frame <= 60 and slot_frames[ANCHOR_SLOT] ~= -1 then
        local af = slot_frames[ANCHOR_SLOT]
        if f_set_rewind then pcall(function() f_set_rewind(af, 0) end) end
        local load_ok, _ = raw_load_slot(ANCHOR_SLOT)
        if load_ok then
            cur_frame        = af
            target_frame     = af
            engine_state     = STATE_PLAYBACK
            is_paused        = false
            reached_eof      = false
            pause_after_seek = false
            pcall(function() emu.speedmode("normal") end)
            eof_grace_frames = 0
            sync_score_at_frame(af)
            sync_gui_state(true)
            return
        end
    end

    -- 分支 B: 向前跳轉 (dest_frame > cur_frame，例如 +1幀、+3秒、+10秒、快進30秒、百分比向後跳)
    if dest_frame > cur_frame then
        -- B1. 目標在已探索範圍內 (dest_frame <= max_seen_frame)
        if dest_frame <= max_seen_frame then
            local best_f, best_s = find_best_snapshot(dest_frame)
            if best_s and best_f > cur_frame then
                if f_set_rewind then pcall(function() f_set_rewind(best_f, 0) end) end
                local load_ok, _ = raw_load_slot(best_s)
                if load_ok then
                    cur_frame = best_f
                    sync_score_at_frame(best_f)
                    if is_pct_jump or (dest_frame - best_f <= BASE_STRIDE) then
                        target_frame     = best_f
                        engine_state     = STATE_PLAYBACK
                        is_paused        = false
                        reached_eof      = false
                        pause_after_seek = false
                        pcall(function() emu.speedmode("normal") end)
                        eof_grace_frames = 0
                        sync_gui_state(true)
                        return
                    end
                end
            else
                -- 【全按鈕防 Desync 核心】：若未載入更新快照且原本處於暫停，必須先載入 SLOT_PAUSE 消除 CPU 偷跑的 1 幀！
                if f_set_rewind then pcall(function() f_set_rewind(cur_frame, 0) end) end
                if was_paused then
                    raw_load_slot(SLOT_PAUSE)
                end
            end
            target_frame     = dest_frame
            engine_state     = STATE_JIT_SEEK
            pause_after_seek = keep_paused and true or false
            pcall(function() emu.speedmode("turbo") end)
            sync_gui_state(true)
            return
        end

        -- B2. 目標超出已探索範圍 (向未知未來探索)
        local best_f, best_s = find_best_snapshot(max_seen_frame)
        if best_s and best_f > cur_frame then
            if f_set_rewind then pcall(function() f_set_rewind(best_f, 0) end) end
            local load_ok, _ = raw_load_slot(best_s)
            if load_ok then
                cur_frame = best_f
            end
        else
            -- 【全按鈕防 Desync 核心】：在最新幀從暫停直接向前快進時，先載入 SLOT_PAUSE 消除 CPU 偷跑的 1 幀！
            if f_set_rewind then pcall(function() f_set_rewind(cur_frame, 0) end) end
            if was_paused then
                raw_load_slot(SLOT_PAUSE)
            end
        end

        target_frame     = dest_frame
        engine_state     = STATE_JIT_SEEK
        pause_after_seek = keep_paused and true or false
        pcall(function() emu.speedmode("turbo") end)
        sync_gui_state(true)
        return
    end

    -- 分支 C: 向後倒帶或原地定位 (dest_frame <= cur_frame)
    local best_f, best_slot = find_best_snapshot(dest_frame)
    if not best_slot or best_f < 0 then
        log_msg("SEEK_ERR: 找不到可用快照 dest=" .. tostring(dest_frame))
        return
    end

    if f_set_rewind then pcall(function() f_set_rewind(best_f, 0) end) end
    local load_ok, load_err = raw_load_slot(best_slot)
    log_msg(string.format("SEEK_LOAD: slot=%d snap_f=%d dest_f=%d ok=%s err=%s",
        best_slot, best_f, dest_frame, tostring(load_ok), tostring(load_err)))

    if not load_ok then
        log_msg("SEEK_ABORT: 載入快照失敗！")
        return
    end

    cur_frame        = best_f
    if dest_frame > best_f then
        target_frame     = dest_frame
        engine_state     = STATE_JIT_SEEK
        pause_after_seek = keep_paused and true or false
        pcall(function() emu.speedmode("turbo") end)
    else
        target_frame     = best_f
        if keep_paused then
            engine_state     = STATE_PLAYBACK
            is_paused        = true
            pause_after_seek = true
            pcall(function() emu.pause() end)
        else
            engine_state     = STATE_PLAYBACK
            is_paused        = false
            pause_after_seek = false
            pcall(function() emu.speedmode("normal") end)
        end
    end
    reached_eof      = false
    eof_grace_frames = 0
    sync_score_at_frame(cur_frame)

    sync_gui_state(true)
end

-- 雙通道輪詢 GUI 指令 (記憶體優先 + 檔案備援)
local function poll_command_dual()
    if f_poll_cmd then
        local ok, c_code, c_val = pcall(f_poll_cmd)
        if ok then
            return (c_code or 0), (c_val or 0)
        end
    end

    local cmd_code = 0
    local cmd_val  = 0
    pcall(function()
        local f = io.open(ipc_cmd_path, "r")
        if f then
            local line = f:read("*l")
            f:close()
            if line and line ~= "" then
                local s_seek = line:match("^SEEK%s+(-?%d+)")
                local s_delt = line:match("^DELTA%s+(-?%d+)")
                local s_pct  = line:match("^PCT%s+(-?%d+)")
                if line:match("^PROBE_EOF") then
                    cmd_code = 5
                    cmd_val  = 0
                elseif line:match("^FFWD") then
                    cmd_code = 6
                    cmd_val  = 0
                elseif s_seek then
                    cmd_code = 1
                    cmd_val  = tonumber(s_seek) or 0
                elseif line:match("^PAUSE") then
                    cmd_code = 2
                    cmd_val  = 0
                elseif s_delt then
                    cmd_code = 3
                    cmd_val  = tonumber(s_delt) or 0
                elseif s_pct then
                    cmd_code = 4
                    cmd_val  = tonumber(s_pct) or 0
                end
                local fw = io.open(ipc_cmd_path, "w")
                if fw then fw:close() end
            end
        end
    end)
    return cmd_code, cmd_val
end

-- 處理 GUI 導播指令
local function process_gui_commands()
    local cmd_code, cmd_val = poll_command_dual()
    if not cmd_code or cmd_code == 0 then return false end

    -- 【全域防死結保險】：只要收到任何 GUI 指令，立即重設 last_seen_fc = -1，確保下一幀 100% 推進
    last_seen_fc = -1

    log_msg(string.format("收到 GUI 指令: code=%d val=%d (cur_frame=%d max_seen=%d)", cmd_code, cmd_val, cur_frame, max_seen_frame))

    if cmd_code == 1 then
        -- SEEK <frame>
        is_fast_forwarding = false
        seek_to_frame(cmd_val, false, false)
        return true
    elseif cmd_code == 2 then
        -- PAUSE / RESUME 切換
        is_fast_forwarding = false
        local c_play, c_rec, c_eof = read_c_status()
        if reached_eof or (c_eof == 1 and c_rec > 500 and cur_frame >= c_rec - 5) then
            -- 全場播畢定格時按 PAUSE：自動回到開局 (0%)
            seek_to_frame(0, false, true)
            return true
        elseif is_paused then
            -- 【無縫零幀差恢復播放】：直接載入 SLOT_PAUSE 並釋放暫停鎖，0 毫秒原地繼續 1x 播放！
            is_paused        = false
            pause_after_seek = false
            eof_grace_frames = 0
            freeze_tick      = 0
            engine_state     = STATE_PLAYBACK
            pcall(function() emu.speedmode("normal") end)
            if f_set_paused then pcall(function() f_set_paused(0) end) end
            if f_set_rewind then pcall(function() f_set_rewind(cur_frame, 0) end) end
            raw_load_slot(SLOT_PAUSE)
            sync_score_at_frame(cur_frame)
            sync_gui_state(true)
            return true
        elseif engine_state == STATE_JIT_SEEK then
            pcall(function() emu.speedmode("normal") end)
            engine_state = STATE_PLAYBACK
            target_frame = cur_frame
            pause_after_seek = false
        else
            pcall(function() emu.speedmode("normal") end)
            raw_save_slot(SLOT_PAUSE)
            is_paused = true
            engine_state = STATE_PAUSED
            if f_set_paused then pcall(function() f_set_paused(1) end) end
            if f_set_rewind then pcall(function() f_set_rewind(cur_frame, 0) end) end
        end
        sync_gui_state(true)
        return true
    elseif cmd_code == 3 then
        -- DELTA <frames>
        is_fast_forwarding = false
        local c_play, c_rec, c_eof = read_c_status()
        if cmd_val > 0 and (reached_eof or (c_eof == 1 and c_rec > 500 and cur_frame >= c_rec - 5)) then
            sync_gui_state(true)
            return true
        end

        local is_single_step = (cmd_val == -1 or cmd_val == 1)
        local base_origin = cur_frame
        if engine_state == STATE_JIT_SEEK and cmd_val > 0 and target_frame > cur_frame then
            base_origin = target_frame
        end

        local dest = base_origin + cmd_val

        if c_eof == 1 and c_rec > 100 then
            if dest >= c_rec - 5 then dest = c_rec - 5 end
        else
            local safe_forward_limit = math.max(max_seen_frame, c_rec) + 1800
            if dest > safe_forward_limit then dest = safe_forward_limit end
        end
        if dest < 0 then dest = 0 end

        seek_to_frame(dest, is_single_step, false)
        return true
    elseif cmd_code == 4 then
        -- PCT <0..99> 百分比跳轉
        is_fast_forwarding = false
        local c_play, c_rec, c_eof = read_c_status()
        if cmd_val <= 0 then
            pending_pct = nil
            seek_to_frame(0, false, true)
            return true
        end
        if c_eof == 1 and c_rec > 100 then
            pending_pct = nil
            local dest = math.floor(c_rec * (cmd_val / 100.0))
            seek_to_frame(dest, false, true)
        else
            pending_pct = cmd_val
            local total_scale = math.max(c_rec, DEFAULT_SCALE_FRAMES)
            local dest = math.floor(total_scale * (cmd_val / 100.0))
            seek_to_frame(dest, false, true)
        end
        return true
    elseif cmd_code == 5 then
        -- PROBE_EOF: 全速探底並直達 True EOF
        is_fast_forwarding = false
        local c_play, c_rec, c_eof = read_c_status()
        if c_eof == 1 and c_rec > 500 then
            seek_to_frame(c_rec - 5, true, false)
            return true
        end
        log_msg("PROBE_EOF_TRIGGERED: 全速探底啟動，以 600 FPS 建立歷史快照索引！")
        local was_paused = is_paused
        reached_eof      = false
        is_paused        = false
        eof_grace_frames = 0
        pending_pct      = nil
        freeze_tick      = 0

        -- 1. 立即釋放 C 底層暫停鎖，防止 g_play_frame 卡死在原幀
        if f_set_paused then pcall(function() f_set_paused(0) end) end

        -- 2. 若有更遠的快照則載入最高快照；若在最新幀且原本為暫停，必須先載入 SLOT_PAUSE 消除 CPU 偷跑的 1 幀！
        local best_f, best_s = find_best_snapshot(max_seen_frame)
        if best_s and best_f > cur_frame then
            if f_set_rewind then pcall(function() f_set_rewind(best_f, 0) end) end
            if raw_load_slot(best_s) then
                cur_frame = best_f
            end
        else
            if f_set_rewind then pcall(function() f_set_rewind(cur_frame, 0) end) end
            if was_paused then
                raw_load_slot(SLOT_PAUSE)
            end
        end

        target_frame     = MAX_CAPACITY_FRAMES
        engine_state     = STATE_JIT_SEEK
        pause_after_seek = true -- 探底完成後自動定格
        pcall(function() emu.speedmode("turbo") end)
        sync_gui_state(true)
        return true
    elseif cmd_code == 6 then
        -- FFWD: 持續快轉切換
        local c_play, c_rec, c_eof = read_c_status()
        if is_fast_forwarding then
            is_fast_forwarding = false
            pcall(function() emu.speedmode("normal") end)
            log_msg("FFWD_TOGGLE: 停止快轉，恢復正常播放")
        elseif reached_eof or (c_eof == 1 and c_rec > 500 and cur_frame >= c_rec - 5) then
            is_fast_forwarding = false
            pcall(function() emu.speedmode("normal") end)
            log_msg("FFWD_TOGGLE: 已在結尾，忽略快轉")
        else
            local was_paused   = is_paused
            is_fast_forwarding = true
            is_paused          = false
            reached_eof        = false
            freeze_tick        = 0
            if f_set_paused then pcall(function() f_set_paused(0) end) end
            if f_set_rewind then pcall(function() f_set_rewind(cur_frame, 0) end) end
            if was_paused then
                raw_load_slot(SLOT_PAUSE)
            end
            pcall(function() emu.speedmode("turbo") end)
            log_msg("FFWD_TOGGLE: 啟動持續快轉！")
        end
        sync_gui_state(true)
        return true
    end
    return false
end

-- ============================================================================
-- 4. 單一原子幀後主迴圈 (對齊黃金基準版：統一在 registerafter 處理指令、載入與存檔)
-- ============================================================================
local function main_frame_after()
    -- 單幀防重入保護 (確保每個模擬器幀只執行一次)
    if emu and emu.framecount then
        local fc = emu.framecount()
        if fc == last_seen_fc and not is_paused and not reached_eof then
            return
        end
        last_seen_fc = fc
    end

    if not anchor_saved and cur_frame == 0 then
        init_snapshot_pool()
        engine_state = STATE_PLAYBACK
        log_msg("初始化快照池完畢 (Slot 1..42 安全模式)，進入正常播放狀態")
    end

    -- 1. 讀取 C 端最新幀號與 EOF 狀態
    local c_play, c_rec, c_eof, c_starving, c_ah_level = read_c_status()
    if not is_paused and c_play and c_play >= 0 then
        cur_frame = c_play
    end
    if cur_frame > max_seen_frame then
        max_seen_frame = cur_frame
    end

    -- 2. 在整幀模擬與中斷完全安定後，優先記錄乾淨快照 (含第 30 幀開局錨點 Slot 1)
    if not is_paused and not reached_eof and c_starving == 0 then
        record_snapshot_at_frame(cur_frame, c_rec, c_eof)
        if cur_frame >= max_seen_frame and (cur_frame % 15 == 0 or cur_frame <= 60) then
            sample_and_record_scores(cur_frame)
        end
    end

    -- 3. 讀取並處理 GUI 遙控指令 (正常/暫停時每幀檢查；快進狂奔時每 10 幀 [約16ms] 檢查一次)
    local is_probing_now = (engine_state == STATE_JIT_SEEK or is_fast_forwarding)
    if (not is_probing_now) or (cur_frame % 10 == 0) then
        if process_gui_commands() then
            -- 指令處理完畢 (可能已執行跳轉)，立刻同步最新幀號並結束當前幀，防止同幀向下誤入撞尾定格！
            local p = read_c_status()
            if p and p >= 0 then cur_frame = p end
            return
        end
    end

    -- 4. 若處於 JIT_SEEK 快轉追趕中：檢查是否已抵達 target_frame 或撞上真實結尾
    if engine_state == STATE_JIT_SEEK then
        local hit_eof = (c_eof == 1 and c_rec > 500 and cur_frame >= c_rec - 2)
        if hit_eof or (cur_frame >= target_frame) then
            if hit_eof and pending_pct ~= nil then
                local pct_to_go = pending_pct
                pending_pct = nil
                local true_dest = math.floor(c_rec * (pct_to_go / 100.0))
                log_msg(string.format("SNAP_BACK_TRIGGERED: EOF撞尾回彈！真總長=%d 回彈目標=%d (%d%%)", c_rec, true_dest, pct_to_go))
                seek_to_frame(true_dest, false, true)
                return
            end

            pending_pct = nil
            is_fast_forwarding = false
            pcall(function() emu.speedmode("normal") end)
            engine_state = STATE_PLAYBACK
            sync_score_at_frame(cur_frame)

            if hit_eof then
                eof_grace_frames = 3 -- 3 幀 normal 速度渲染最終勝利畫面
                pause_after_seek = true
                log_msg(string.format("JIT_SEEK_HIT_EOF: 成功抵達真實結尾 cur=%d c_rec=%d", cur_frame, c_rec))
                sync_gui_state(true) -- 撞尾瞬間強制原子落盤！
            elseif pause_after_seek then
                eof_grace_frames = 3
                sync_gui_state(true)
            end
        end
    end

    -- 4.5 若處於極速快錄 (Turbo Fast-Recording) 階段：維持 emu.speedmode("turbo")；結束瞬間自動煞車恢復 1x normal！
    if f_is_turbo_rec and not is_paused and not reached_eof then
        local ok_tr, is_tr = pcall(f_is_turbo_rec)
        if ok_tr and is_tr == 1 then
            was_turbo_recording = true
            pcall(function() emu.speedmode("turbo") end)
        elseif was_turbo_recording then
            was_turbo_recording = false
            pcall(function() emu.speedmode("normal") end)
            log_msg("TURBO_REC_FINISHED: 極速快錄結束，已自動平滑切回 1x normal 速度！")
        end
    end

    -- 5. 處理畫面重繪緩衝期 (Grace Frames)
    if eof_grace_frames and eof_grace_frames > 0 then
        eof_grace_frames = eof_grace_frames - 1
        if eof_grace_frames == 0 then
            raw_save_slot(SLOT_PAUSE)
            if pause_after_seek or (c_eof == 1 and cur_frame >= c_rec - 2) then
                is_paused = true
                pause_after_seek = false
                if c_eof == 1 and cur_frame >= c_rec - 2 then
                    reached_eof = true
                end
            end
        end
        sync_gui_state()
        return
    end

    -- 6. 處於播畢定格狀態 (STATE_EOF_FREEZE) 或手動暫停狀態：確保畫面與角色 100% 絕對靜止！
    if (reached_eof and is_paused) or is_paused then
        -- 1. 載入在 eof_grace_frames 結束瞬間存下的 SLOT_PAUSE，
        --    讓 68000 CPU 永遠釘死在 07:52 瞬間，角色連 1 根手指頭都不會再動！
        raw_load_slot(SLOT_PAUSE)

        -- 2. 同步鎖定 C 端的 g_play_frame，每 60 幀同步一次即可，杜絕磁碟 I/O 狂寫日誌！
        freeze_tick = (freeze_tick or 0) + 1
        if freeze_tick == 1 then
            if f_set_paused then pcall(function() f_set_paused(1) end) end
            if f_set_rewind then pcall(function() f_set_rewind(cur_frame, 0) end) end
        end

        if freeze_tick % 15 == 0 then
            sync_gui_state()
        end
        return
    end

    -- 7. 正常播放或持續快轉途中撞上真實結尾 (EOF)：嚴格限制 cur_frame 真正位於最末尾才定格
    if c_eof == 1 and c_rec > 500 and cur_frame >= (c_rec - 2) and not reached_eof and not is_paused then
        is_fast_forwarding = false
        pcall(function() emu.speedmode("normal") end)
        engine_state = STATE_PLAYBACK
        eof_grace_frames = 3
        pause_after_seek = true
        sync_gui_state()
        return
    end

    -- 【動態雙軌架構】平時每 15 幀才同步 GUI (磁碟 I/O 降低 93%)；
    -- 其餘幀僅呼叫 C 核心 (未錄影時 C 端不寫檔、立即返回)，使錄影期間 60 FPS 幀幀直出。
    if cur_frame % 15 == 0 then
        sync_gui_state()
    elseif f_update_state then
        local st_now = (engine_state == STATE_JIT_SEEK or is_fast_forwarding) and STATE_JIT_SEEK or STATE_PLAYBACK
        local scr_w = (emu.screenwidth and emu.screenwidth()) or 0
        local scr_h = (emu.screenheight and emu.screenheight()) or 0
        pcall(function() f_update_state(cur_frame, max_seen_frame, 0, st_now, target_frame, scr_w, scr_h) end)
    end
end

if emu.registerexit then
    emu.registerexit(function()
        set_audio_mute(0)
    end)
end

if emu.registerafter then
    emu.registerafter(function()
        local ok, err = pcall(main_frame_after)
        if not ok then
            log_msg("CRITICAL_AFTER_ERR: " .. tostring(err))
        end
    end)
end
