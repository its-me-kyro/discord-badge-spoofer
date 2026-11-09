# Discord Badge Spoofer

> **I am against using this tool.**

This repository exists only as a technical demonstration.  
I have **never** used this tool on any of my accounts and I will never use it.

---

### My position

- Profile badges are meaningless.  
- Even large creators (for example Beluga) never had fully maxed badges. Nobody cares.
- Using this tool is a reliable way to get your account suspended or permanently banned.
- If your goal is to get suspended, then go ahead and run it.
- I modified this code mainly so the original author does not gain free subscribers and attention from it.

I am not promoting the use of this software.  
I am documenting it and stating clearly that it violates Discord’s Terms of Service.

**Discord Terms of Service:** https://discord.com/terms

---

## Warning

This tool deliberately violates Discord’s Terms of Service by sending fake analytics events.

- You **will** risk permanent loss of the account.
- Badges take 1–2 days to appear (if they appear at all).
- Discord can detect and ban for this at any time.
- I take no responsibility for anything that happens to accounts that use it.

If you still decide to run it, you do so entirely at your own risk.

---

## How to get your Discord token (desktop)

1. Open the Discord desktop app or Discord in a browser.
2. Press `Ctrl + Shift + I` (Windows/Linux) or `Cmd + Option + I` (macOS) to open DevTools.
3. Go to the **Application** tab (Chrome) / **Storage** tab (Firefox).
4. On the left side open **Local Storage** → `https://discord.com`.
5. In the filter/search box type: `token`
6. You will see several entries.  
   Copy the value of the key that is simply called **`token`** (the middle one).  
   **Do not** copy the one named `tokens` or any other key.
7. That long string is your account token. Keep it private.

The tool stores the token and cookie only on your own machine in the file `science_state.json`. Nothing is sent to me or any third party except Discord’s official API.

---

## How to get the cookie

You also need a `cf_clearance` cookie.

1. While logged into Discord, open DevTools → Network tab.
2. Reload the page or click anything.
3. Click any request going to `discord.com`.
4. Find the request headers and copy the entire `cookie` value (it must contain `cf_clearance`).

---

## Requirements

- Python 3.10 or newer
- No extra packages needed (standard library only)

---

## How to run (Windows)

1. Extract the folder.
2. Open the folder in File Explorer.
3. Click the address bar at the top, delete everything, type `cmd` and press Enter.
4. Check Python:
   ```bat
   python --version
   ```
   If it is not installed, download it from https://www.python.org/downloads/  
   and make sure you check **“Add python.exe to PATH”** during installation.
5. Run:
   ```bat
   python spoofer.py
   ```

---

## Menu

1. Claim playtime on a batch of games  
2. Add hours to specific games (search by name)  
3. Refresh auth / update cookie  
4. Set fingerprint (optional, Windows only)  
5. Exit  

---

## About the author of this modified version

- X / Twitter: [@its_me_kyro](https://x.com/its_me_kyro)
- I do not use this tool.
- I do not encourage anyone to use this tool.
- I released this modified version so the original project does not continue to be promoted for free.

---

## License

MIT License – see the `LICENSE` file.

You are free to use, modify and redistribute under the terms of the MIT license.  
I still strongly advise against actually running it on any account you care about.
