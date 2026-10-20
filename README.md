# FightcadeRewindPlayer ⏪⏩

**FightcadeRewindPlayer** 是一款專為 Fightcade / FBNeo 回放打造的無縫時光倒流與進度跳轉控制播放器。

透過 DLL 代理掛鉤（Proxy Hook）與 Lua 協同架構，讓原本只能單向線性播放的回放錄像，實現如 YouTube 播放器般的**任意時間倒帶、快進、0 幀完美暫停與自由跳轉**！

---

## ✨ 核心特色 (Key Features)

1. **無縫時光倒流 (Seamless Rewind & Fast-Forward)**：
   - 支援 1 秒、5 秒、10 秒、30 秒快速前進 / 倒退。
   - 支援 1 幀精準步進，重播格鬥遊戲精準立回與確反細節。
2. **0 幀偷跑修復 & 零 Desync (Zero Desync & Pause Head Lock)**：
   - 專利級 GGPO 播放頭鎖死技術，暫停期間維持完美 0 幀偷跑。
   - 解除暫停時自動對齊記憶體快照管線，確保永遠不脫節、不亂碼。
3. **安全透明的快照探底機制 (Smart Snapshot Indexing)**：
   - 點擊「探底並解鎖進度條」後，模擬器將高速步進建立全場記憶體快照。探底完成即解鎖時間軸滑桿自由拖曳。
4. **極致綠色便攜 (100% Portable & Non-Invasive)**：
   - 單一執行檔免安裝，無任何外部相依。
   - 啟動時自動備份原廠 DLL，結束關閉時自動還原乾淨環境，完全不殘留任何修改。
5. **深色直覺 GUI (Modern Dark UI)**：
   - 整合微軟正黑體繁體中文介面，即時顯示幀號、進度條、當前狀態與導播指令即時日誌。

---

## 🚀 快速開始 (Quick Start)

### 一般玩家使用方式：
1. 從 [Releases](https://github.com/Kimwu2000p/FightcadeRewindPlayer/releases) 下載最新版的 `FightcadeRewindPlayer.exe`。
2. 將該執行檔放入您的 **Fightcade 安裝根目錄**（與 `Fightcade2.exe` 同一目錄）。
3. 雙擊開啟 `FightcadeRewindPlayer.exe`。
4. 在 Fightcade 內正常點擊回放開始觀看，播放器將自動偵測並點亮控制介面！

> 💡 **操作指南**：
> 首次觀看建議先點擊「探底並解鎖進度條」，待進度達 100% 後即可隨心所欲拖曳下方時間軸跳轉任意精彩回合！

---

## 🛠️ 開發與編譯 (Building from Source)

專案結構如下：
- `src/proxy_ggpo/`：GGPO.dll 代理掛鉤 C 原始碼，攔截控制幀推進與暫停。
- `src/lua/`：導播核心腳本，負責與 FBNeo 記憶體管線溝通、保存與載入快照。
- `tools/pack_player.ps1`：一鍵將 DLL 與 Lua 編碼內嵌並生成綠色執行檔的打包工具。
- `FightcadeRewindPlayer.bat`：主控制介面腳本。

### 編譯需求：
- GCC (MinGW-w64 32-bit i686) 用於編譯 32-bit proxy DLL。
- PowerShell 5.1+ 與 PS2EXE。

---

## ⚠️ 相容性與免責聲明 (Compatibility & Disclaimer)

- **測試平台**：本工具目前以 **Neo-Geo《餓狼傳說 群狼之證 (Garou: Mark of the Wolves)》** 為主要深度測試與調校標的，其他機台或遊戲平台尚待社群測試回報。
- **版權說明**：本專案為社群自製非商業開源工具，**不包含**任何未授權之遊戲 ROM、BIOS 或 Fightcade 原版程式碼。所有遊戲版權均屬原版權所有者（SNK 等公司）。

---

## 🤝 致謝與社群切磋 (Credits & Community)

- 本播放器由作者搭配 **Google Gemini AI** 深度協同開發完成。
- **作者 Fightcade ID**：`kimwu2000p`，歡迎各位格鬥同好上線一起切磋交流！
- 歡迎提交 Issue 或 Pull Request 協助相容更多遊戲！

---

## 📄 授權條款 (License)

本專案採用 [MIT License](LICENSE) 條款開源。