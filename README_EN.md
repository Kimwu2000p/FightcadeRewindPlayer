# FightcadeRewindPlayer ⏪🎬⏩

[繁體中文版 (README.md)](README.md)

**FightcadeRewindPlayer** is an advanced, broadcast-grade **Rewind & Video Capture Engine (v1.1)** tailored specifically for Fightcade and FBNeo arcade replays.

Powered by a lightweight DLL Proxy Hook (`ggponet.dll`), Direct Named Pipe video streaming, and asynchronous remuxing, it elevates linear replay playback into a full-featured video production workflow: **seamless timeline scrubbing, fast-forwarding, frame-by-frame stepping, 0-frame pause locking, and multi-preset 60fps MP4 video exporting**!

---

## 🚀 Quick Start

### General Player Setup:
1. Download the latest release executable `FightcadeRewindPlayer.exe` from [Releases](https://github.com/Kimwu2000p/FightcadeRewindPlayer/releases) (or run/inspect `FightcadeRewindPlayer.bat` directly).
2. Place `FightcadeRewindPlayer.exe` inside your **Fightcade root folder** (the folder containing `emulator`, alongside `Fightcade2.exe`).
3. Copy any replay URL from your browser or Fightcade lobby (e.g. `https://replay.fightcade.com/fbneo/...`), or use the built-in Match Finder.
4. Launch `FightcadeRewindPlayer.exe` (clipboard URL is auto-detected), and click **"▶ Launch Replay"** to mount the rewind engine!

---

## 🎛️ Director Remote Controls

* ⚡ **Probe to EOF**: Fast-forward at 500~600 FPS to match end & unlock timeline seeking.
* **PCT Jump (0% ~ 90%)**: Instantly jump to any match percentage point once probed.
* ⏪ / ⏩ **Seek Controls**: Step backward/forward by 3s, 10s, 30s with zero desync.
* ▶ / || **Play / Pause**: Freeze frame with 0-frame drift; click again to resume smoothly.
* **-1f / +1f Step**: Frame-by-frame stepping to analyze hitboxes, spacing, and links.

---

## 🎬 MP4 Recording Studio (v1.1 Flagship Feature)

Export any highlight clip (custom start/end seconds) or full match to high-quality 60fps MP4 video:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ [Clip Range]  ○ Full Replay  ● Custom Clip  [In: 00:02.0]  [Out: 00:12.0] (10.0s)│
├────────────────────────────────────────────────────────────────────────┤
│ A. Resolution:  [ 🕹️ 1. Native 1x (Auto-detect NEOGEO / CPS1~3 / Arcade) ▼] │
│ B. Render Mode: [ 🕹️ 1. AdvanceMAME Scale3x + Scanlines [1:1 Authentic]  ▼] │
│ C. HUD Style:   [ ⭐ 1. Modern Bar HUD (Semi-Black Bar + Scoreboard)      ▼] │
├────────────────────────────────────────────────────────────────────────┤
│ Save Path:     [ C:\...\Fightcade_Clips                          ] [Browse] [Open]│
│ [● FFmpeg Ready]   [Set FFmpeg]   [⚡ Turbo Rec]   [ ● Export Clip ]   [ ▲ ]   │
└────────────────────────────────────────────────────────────────────────┘
```

* ⚡ **Turbo Fast-Record**: Render in background at maximum hardware speed (uncheck for 1x real-time watching and recording). Both output identical frames, audio, and quality.
* **A. Output Resolution (4 Options)**:
  1. **Native 1x**: Pixel-perfect arcade resolution (NeoGeo `320×224`, CPS1~3 `384×224`, PGM `448×224`).
  2. **720P HD**: `1280×720` HD (aspect-correct 960×720 centered with black pillars).
  3. **1080P Full HD**: `1920×1080` Full HD (aspect-correct 1440×1080 centered).
  4. **1440P (2K) QHD**: `2560×1440` QHD (forces YouTube's premium VP9 encoder, eliminating motion blur on high-speed arcade fighting games).
* **B. Render Mode (4 Visual Styles)**:
  1. **Official AdvanceMAME Scale3x + Scanlines**: 1:1 authentic Fightcade edge-smoothing with fine scanlines.
  2. **CRT Aperture Grille**: Integer prescale + classic 15kHz CRT scanline raster.
  3. **Razor Sharp Pixels**: Zero scanlines! Ultra-crisp integer prescale + esports sharpening.
  4. **Smooth Bicubic**: Zero scanlines! Gentle bicubic interpolation.
* **C. Top Scoreboard & Rank HUD**:
  - Automatically reads 1P/2P IDs, live scores, FT format, and official Fightcade Rank badges `[S / A / B / C / D / E]` directly from emulator memory.
  - Automatically hides and centers when unranked. Also supports classic 8×8 arcade pixel font or clean screen (no HUD).

---

## 📦 Placement & How to Get FFmpeg (Free)

The MP4 recording feature is powered by the open-source **FFmpeg** media engine (not needed if only watching and rewinding):

### 1. Free Official Sources:
* **Option A (Official Portable ZIP - Recommended)**:
  Visit GitHub FFmpeg-Builds releases:
  [https://github.com/BtbN/FFmpeg-Builds/releases](https://github.com/BtbN/FFmpeg-Builds/releases)
  Download `ffmpeg-master-latest-win64-gpl.zip` (or `ffmpeg-release-essentials.zip` from [https://www.gyan.dev/ffmpeg/builds/](https://www.gyan.dev/ffmpeg/builds/)), extract `bin/ffmpeg.exe`, and place it in the application folder.
* **Option B (One-Line Winget Install)**:
  Open Command Prompt or PowerShell and run:
  ```cmd
  winget install Gyan.FFmpeg
  ```
  Restart this application and it will be detected automatically.

### 2. Path Configuration:
- Place at `Fightcade	oolsfmpeg.exe` or `Fightcadefmpeg.exe`.
- Or click the **"Set FFmpeg"** button in the recording drawer to select `ffmpeg.exe` anywhere on your computer.

---

## 💡 Why is 'Probe to EOF' Required Before Free Seeking? (Tech Info)

Fightcade replays are **live input packet streams** rather than pre-rendered video files. At startup, the emulator only has the first few seconds of inputs. Clicking "⚡ Probe to EOF" buffers all packets at up to 600 FPS and builds a memory snapshot index (Slot 1..42 pool), unlocking 100% free seeking across the entire match!

---

## 🕹️ Multi-Platform Hardware Compatibility

Fully verified on:
* **Neo-Geo** (`320×224`, e.g., *Garou: Mark of the Wolves*, *KOF '98 / 2002*, *The Last Blade 2*)
* **CPS1 / CPS2 / CPS3** (`384×224`, e.g., *Street Fighter III: 3rd Strike*, *SF Alpha 3*)
* **PGM** (`448×224`, e.g., *Knights of Valour*, *Oriental Legend*)
* Features dynamic pitch detection, dual-hash anchor protection, and exact hardware framerate synchronization.

---

## 🛡️ Portable Zero-Residue Design, Antivirus Guide & Audio Tips

### 1. Zero-Residue Portable Design:
Single portable executable. Official `ggponet.dll` is backed up on launch and restored automatically on exit, never affecting online ranked play.

### 2. Antivirus False-Positive Guide:
This is a 100% open-source tool (all source code is public in this repository, and `FightcadeRewindPlayer.bat` can be inspected and run directly). Because the single-file EXE embeds a compressed proxy DLL, interacts with the emulator process, and does not have a costly commercial EV code-signing certificate, some antivirus software may flag it heuristically. Whitelisting takes just 3 steps:
1. Open **Windows Security** -> **Virus & threat protection** -> **Manage settings**.
2. Scroll down to **Exclusions** -> click **Add or remove exclusions**.
3. Click **Add an exclusion** -> select **Folder** -> select your Fightcade folder.

### 3. Audio Troubleshooting:
In-process WASAPI mute silences fast-forward noise and unmutes on 1x playback. If Windows Volume Mixer ever locks mute on `fcadefbneo.exe` after a crash:
- Open Windows **Settings** -> **System** -> **Sound** -> **Volume Mixer** and click **"Reset sound devices and volumes for all apps"**.

---

## 🤝 Credits & Community

- Co-engineered and reverse-engineered by **Kim** with **Google DeepMind Gemini AI**.
- **Author's Fightcade ID**: `kimwu2000p`
- GitHub Project: [https://github.com/Kimwu2000p/FightcadeRewindPlayer](https://github.com/Kimwu2000p/FightcadeRewindPlayer)
- Feel free to challenge, chat, and enjoy retro arcade fighting games together! :)

---

## 💖 Special Thanks

Heartfelt thanks to the **[Fightcade](https://www.fightcade.com/) Team** for creating such an extraordinary matchmaking platform and rollback netplay ecosystem for retro fighting game enthusiasts worldwide. Without Fightcade's remarkable GGPO architecture and vibrant community, this project would not have been possible. Huge respect to the developers who keep the classic fighting game spirit alive!

---

## 📄 License

This project is open-sourced under the [MIT License](LICENSE).  
This is a fan-made, non-commercial tool and does not contain any unauthorized game ROMs or BIOSes. All game trademarks belong to their respective owners.
