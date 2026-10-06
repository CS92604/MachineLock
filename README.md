# MachineLock

Offline, machine-bound license keys for Windows apps. No server, no accounts. C++ and C#, Windows built-ins only.

There is no server to run, no account to create, and no internet connection needed, now or ever. This repo is a working demo with three programs:

| Program (release) | Source file | Who has it | What it is |
|---|---|---|---|
| **ExampleShippedApp.exe** | `ExampleShippedApp.cpp` | Your customers | A basic calculator that refuses to open until it has a valid license key. |
| **MachineCodeTool.exe** | `MachineCodeTool.cpp` | Your customers (optional) | A tiny helper that shows the customer's machine code and copies it to the clipboard, ready to send to you. |
| **PrivateOwnerApp.exe** | `PrivateOwnerApp.cs` | Only you | The tool that turns a customer's machine code into a license key. |

Three source files, three releases. Nothing else is needed to build or use it.

```
ExampleShippedApp/ExampleShippedApp.cpp    the app your customers run
MachineCodeTool/MachineCodeTool.cpp        optional helper, copies the machine code for them
PrivateOwnerApp/PrivateOwnerApp.cs         your key-making tool (keep it private)
Release/                                   the three built exes, ready for a GitHub Release (not committed)
```

> **Status: proof of concept.** It is a complete, working system, written to be lifted into your own app. See [Using it in your own app](#part-3-using-it-in-your-own-app) and [Making it stronger](#making-it-stronger).

**Contents:** [Try it](#try-it-test-key) | [Simple version](#part-1-the-simple-version) | [Technical version](#part-2-the-technical-version) | [Build](#build) | [Use it in your own app](#part-3-using-it-in-your-own-app) | [Pros and cons](#pros-and-cons)

## Try it: test key

Want to see it work without building anything? This is a **test key**. It is bound to no computer, so it works on any PC, and it expires.

```
wKWlbAAAAABDQUxDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcJc3b7ME3XLUQAIRtWLwLDa0M5wgJm+jqIv5L2cn6x+xx0uRo6c2uqQvDYUKyZuvEaeZDrlHSkowi6Ok8eOvcQ==
```

Paste it into the activation screen of `ExampleShippedApp.exe` (or save it as `license.key` next to the exe). **Valid through 2027-10-05** (the end of that day, in the issuer's time zone). It works with the released `ExampleShippedApp.exe` or any build of this repo's source, because both carry the demo public keys. If you replace the demo keys it stops working: make a new one with **Test key (any PC)** in PrivateOwnerApp and update this block.

To try the full flow (machine code in, license out) build from source with your own keys, see [Build](#build). Licenses from your own PrivateOwnerApp only unlock a build that carries your public keys.

---

## Part 1: The simple version

*No technical background needed.*

### The idea

Think of a hotel key card. The front desk programs it for **one specific room**. If you hand your card to a friend, it will not open their room, because it was never made for their room.

This system works the same way, except the "room" is a **computer**.

### What happens

**For the customer**

1. They open the calculator for the first time.
2. Instead of the calculator, they see a screen with a long code of letters and numbers. This is their computer's **machine code**. It is like their room number.
   (Prefer something smaller? They can run **MachineCodeTool** instead. It pops up the same code and copies it to the clipboard for them.)
3. They send that code to you (email, chat, anything).
4. You send back a **license key**.
5. They paste the key into the box (or drop the `license.key` file next to the app). The calculator opens.

**For you (the owner)**

1. Open **PrivateOwnerApp**.
2. Paste the customer's machine code. The app tells you whether it looks healthy (green), weak (orange), or unusable (red). See [What if the machine code is "weak"?](#what-if-the-machine-code-is-weak).
3. Choose an expiry date, or "Never expires".
4. Click **Generate key**. Copy it, or save it as `license.key`, and send it to the customer.

**Handing out a free trial?** Press **Test key (any PC)** instead. It needs no machine code: you choose an expiry date and it makes a key that works on any computer until that date. It cannot be made without an expiry.

### What if the machine code is "weak"?

A computer's machine code is built from up to four hardware details. Some computers (virtual machines especially, and a few cheap motherboards) hide some of them. When that happens, the owner app shows the code in **orange**, and a license tied to it would be easier to fool and would stop working if either remaining detail changed.

What the owner app does about it:

- **Red** (none of the four details found, or the text is not a machine code at all): it refuses to make a key.
- **Orange** (one or two details found): it refuses too, unless you tick **Issue anyway**, and even then only when you set an **expiry date**. "Never expires" is not allowed for a weak key.
- The **Recent licenses** list marks these keys as `WEAK`, so you can find and recheck them when they expire.

Best fix: ask the customer to run **MachineCodeTool** on a real PC (not a virtual machine) and send that code instead.

### What if they share the key?

If your customer copies the key to a friend, **it will not work on the friend's computer**. The key was made for one computer only. You do not need to watch for sharing, because a shared key is just a dead file.

### Why it is hard to fake

The key is **digitally signed** with a secret that only you hold. Nobody can write a new key, or change the details in one, without that secret. If someone changes even one character of a key, it stops working.

### What it cannot do

Be honest about the limits:

- Someone with real hacking skill can edit the program itself to skip the check. No offline system can fully stop this. You can make it difficult/annoying to circumvent (like adding more key checks), but not impossible (More in [Cons](#cons).)
- A customer who gives their friend remote access to their own PC can share the app that way.
- You have to hand out keys by hand. There is no "buy now, get key instantly" button.

---

## Part 2: The technical version

### Design goals

- No server, no network calls, works forever with no updates.
- Keys cannot be forged without the owner's private key.
- A license is bound to one machine, with tolerance for a single hardware change.
- No third-party code. Everything uses Windows built-ins (CNG, registry, SMBIOS).

### Architecture

```
  PrivateOwnerApp (C#, WinForms)                 ExampleShippedApp (C++, Win32)
  -----------------------------------            ------------------------------
  issuer.key  (ECDSA P-256 private)              kPub[]      (2 public keys, compiled in)
  spare.key   (backup signing key)               license.key (next to the exe, or %APPDATA%)
  asset.key   (16-byte app secret K)
        |                                                ^
        |   machine code (96 B, base64)                  |
        +<-----------------------------------------------+  customer sends this
        |
        +--- license (184 B, base64) --------------------> owner sends this back (but cannot generate a code themselves)
```

Two apps plus a helper, one shared file format, one-time human-in-the-loop exchange. After activation the shipped app never talks to anything.

The fingerprint code is one marked block that appears identically in `ExampleShippedApp.cpp` and `MachineCodeTool.cpp` (so each file stands alone). Keep the two copies identical: if they ever computed the machine code differently, valid keys would stop matching.

### Machine fingerprint

On startup the shipped app (and `MachineCodeTool`) reads four identifiers:

| Slot | Identifier | Source |
|---|---|---|
| 0 | `MachineGuid` | `HKLM\SOFTWARE\Microsoft\Cryptography` (64-bit view) |
| 1 | SMBIOS system UUID | `GetSystemFirmwareTable('RSMB')`, structure type 1 |
| 2 | Baseboard serial | SMBIOS structure type 2 |
| 3 | Disk serial | the disk Windows is installed on (a `\\.\C:` style volume handle, `IOCTL_STORAGE_QUERY_PROPERTY`), or failing that the first `PhysicalDriveN` that reports a serial. No admin needed |

Each value is trimmed. Placeholder values (`To Be Filled By O.E.M.`, `Default string`, all-zero or all-same-character values, etc.) are treated as **unavailable** and become an all-zero slot. Otherwise the value is hashed with SHA-256 and split:

- `H1` = first 8 bytes, **public**. It goes into the license in the clear and is used for matching.
- `H2` = next 16 bytes, **secret**. It never appears in the license and is used to unwrap `K`.

The machine code shown to the user is `H1[4] || H2[4]` = 32 + 64 = **96 bytes**, shown as 128 base64 characters.

### License format

```
license = base64( payload[120] || signature[64] )          // 184 bytes -> 248 chars

payload:
  0    8   expiry, u64 little-endian unix seconds, 0 = never
  8    8   product tag ("CALC" zero-padded)
  16  32   H1 x 4        public id hashes (zero = slot unavailable)
  48  64   W  x 4        W_i = K xor H2_i  (16 bytes each, zero if slot unavailable)
  112  8   SHA-256(K)[0..8]   check value so a wrong K is rejected

signature = ECDSA-P256( SHA-256(payload) ), raw r||s, 64 bytes
```

`K` is a 16-byte per-product secret generated once and stored in `asset.key`. A license "wraps" `K` separately under each machine slot's secret hash.

A **test license** has all four `H1` slots, all four `W` slots and the `K` check set to zero (it names no machine), and it must carry an expiry. It is signed like any other license, so only the owner can make one.

### Verification (ExampleShippedApp)

In order, and any failure rejects silently (no error text to search for):

1. Strip all whitespace, base64-decode, require **exactly 184 bytes**.
2. Verify the signature over `payload[0..120)` against each embedded public key (primary, then spare), using Windows CNG (`BCryptVerifySignature`). **Fields are read only after this passes.**
3. Check the product tag.
4. Rebuild the local fingerprint. Count slots available in the license (`have`) and slots whose `H1` matches this PC (`hits`). If `have == 0` it is a test license: accept it only if it has an expiry that has not passed, and it yields no `K`. Otherwise require `hits >= min(have, 3)`.
5. For each matching slot, compute `K' = W_i xor H2_i(local)` and accept the first one whose `SHA-256(K')[0..8]` equals the check value.
6. Check expiry (below).
7. On success, `K` is held in memory as `gK`.

Why `3 of 4`: a PC that is reinstalled (new `MachineGuid`) or gets a new disk still matches on the other three. Cloned Windows images that share a `MachineGuid` still differ on firmware and disk IDs.

### Weak machine codes (failsafes)

A machine code is **strong** with 3 or 4 usable slots, **weak** with 1 or 2, and **unusable** with 0 or when it does not decode to 96 bytes. The checks live in `Issuer.Inspect` / `Issuer.Issue` in `PrivateOwnerApp.cs`, so they apply no matter how a key is requested:

| Case | Owner app behavior |
|---|---|
| Invalid or 0 usable slots | Refused with the reason shown. |
| Weak, "Issue anyway" not ticked | Refused. The override box only appears for weak codes. |
| Weak, ticked, "Never expires" on | Refused: a weak binding must have an expiry date. |
| Weak, ticked, expiry set | Issued, with a visible WEAK warning. |

Every issue is logged to `issued.csv` with its usable-slot count, and the Recent list marks weak ones.

On the app side a weak license is stricter, not looser: the match rule is `hits >= min(have, 3)`, so with 2 slots in the license both must match, and `K` must still unwrap from a matching slot. The trade-off is that fewer IDs means an easier spoof and a lockout if either ID changes. The gate limits how often that happens, it cannot make a weak binding strong.

### Expiry and clock rollback

If the license has an expiry, the app compares it to the system clock. To defeat setting the clock back, the highest time ever seen is stored in **two** places (registry `HKCU\Software\ExampleShippedApp\Seen` and `%APPDATA%\ExampleShippedApp\seen.dat`). If `now + 1h < lastSeen`, the license is rejected. While running, the license is re-checked every 60 seconds, so a key that expires while the app is open locks it. The owner picks a date, and the key is valid through the end of that day in the owner's time zone.

### Where `license.key` lives

The app looks next to the exe first, then in `%APPDATA%\ExampleShippedApp\`, and uses whichever holds a valid key. Activating saves next to the exe, and falls back to `%APPDATA%` when the install folder is read-only (for example Program Files).

### Key management

| File (in `PrivateOwnerApp\`) | Contents | If lost or leaked |
|---|---|---|
| `issuer.key` | Primary ECDSA P-256 private key | Leaked: anyone can forge licenses. Lost: use the spare. |
| `spare.key` | Backup signing key, public half also compiled in | Keep **offline**. Move it back next to the exe if the primary is lost. |
| `asset.key` | The 16-byte secret `K` | Lost: no new licenses can be issued. Back it up. |
| `public.txt` | The two public key rows to paste into `kPub` in `ExampleShippedApp.cpp` | Public, safe. |
| `issued.csv` | Log of every license issued, with its usable-ID count (test keys are marked) | Your reissue record. |

All private files are plaintext on disk by design (a forgotten passphrase would be as fatal as a lost key when no updates are possible). Keep them offline and backed up. They are in `.gitignore`.

### What `K` is for

`K` is a secret that only a matching machine can recover. A real application would use it to **decrypt something it cannot run without** (a model, data file, content pack). Then patching out the license check is not enough, because the data stays encrypted. **ExampleShippedApp does not use `K`**: it is only a calculator, so patching `LicenseOk()` opens it. The mechanism is there for you to hook in.

### Build

Requirements: Windows 10/11, Visual Studio 2019 or newer (Community is fine) with the "Desktop development with C++" workload, and the .NET Framework 4 C# compiler that ships with Windows. Each program is one source file compiled with one command. Built and tested with VS 2022; the code is plain C++14 and every flag is VS 2015 or newer, so 2019 should be fine.

**1. PrivateOwnerApp** (any command prompt, in the folder with `PrivateOwnerApp.cs`):

```bat
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:winexe /out:PrivateOwnerApp.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Core.dll PrivateOwnerApp.cs
```

Run it. On first run it offers to create `issuer.key`, `spare.key`, `asset.key` and `public.txt` (it refuses to overwrite existing ones), then shows the two public key rows. **Move `spare.key` off the PC and back up `asset.key` immediately.**

**2. Paste the public rows** into `kPub` in `ExampleShippedApp.cpp`, replacing the demo rows. (The **Public keys...** button shows them again any time.)

**3. The two C++ programs** (from the "x64 Native Tools Command Prompt" that comes with your Visual Studio, each in its own folder):

```bat
cl /O2 /MT /EHsc /utf-8 /GS /guard:cf ExampleShippedApp.cpp /link /SUBSYSTEM:WINDOWS /DYNAMICBASE /NXCOMPAT
cl /O2 /MT /EHsc /utf-8 /GS /guard:cf MachineCodeTool.cpp /link /SUBSYSTEM:WINDOWS /DYNAMICBASE /NXCOMPAT
```

Ship only `ExampleShippedApp.exe`, plus `MachineCodeTool.exe` if you want to offer the helper. Never ship `PrivateOwnerApp.exe` or any `.key` file.

The libraries each file needs are named inside the source (`#pragma comment`), so no extra linker flags are required.

---

## Part 3: Using it in your own app

### Adding it to your app

1. Copy the license code from `ExampleShippedApp.cpp` into your app: the fingerprint block, `Verify`, `UnB64`, `NotExpired`, `LicenseOk`, and the `license.key` helpers (`LicenseFound`, `SaveLicense`). Keep the `#pragma comment(lib, ...)` lines.
2. Run PrivateOwnerApp, create your keys, and paste the public rows into `kPub`.
3. Give every product its own tag (`kTag` in the C++ source, `Tag` in `PrivateOwnerApp.cs`).
4. At startup call `LicenseFound()`. If it fails, show your activation screen with the machine code (`B64` of `Mach`), or tell the user to run `MachineCodeTool`. Re-check on a timer, as the example does.
5. Make something real depend on `gK` (see below), then ship.

### Making it stronger

Roughly cheapest first. None of these make a patched exe impossible, they make it more work.

1. **Make it app-specific with an app code.** Pick a random code of 6 or more characters per product (for example `7QX3KD`), compile it into the fingerprint block, and hash it together with every ID:

   ```cpp
   static const char kAppCode[] = "7QX3KD";     // unique per product, identical in the app and MachineCodeTool

   // in Slot(), after the placeholder check:
   std::string salted = std::string(kAppCode) + s;
   Sha256(salted.data(), (ULONG)salted.size(), h);
   ```

   Now a machine code or license made for app A is useless in app B, even if you reuse a keypair, and the machine codes of different products no longer match each other. It is a salt, not a secret (it sits in the exe), so it separates products and does not stop a determined attacker.
2. **Add an activation code the user types.** Choose a short random code (6 characters is plenty) when you issue each license, send it **separately** from the key, and fold it into the key wrap, for example `W_i = K xor H2_i xor SHA-256(code)[0..16]`. The app asks for it at activation. A key file that leaks without its code is then useless, and it is a natural place to tie the license to a password your app already has.
3. **Make the app need `gK`.** Encrypt something the app cannot run without (a model, a data file, level content) under `K`, and decrypt it with `gK` at runtime. Patching out the check then leaves a broken app. This is the single biggest improvement over a plain yes/no check.
4. **Spread the checks, and do not use one boolean.** Call the check from several places and at the moment a feature is used, not only at startup. Have the result drive behavior (decrypt, compute, unlock) rather than a single `if` an attacker can flip.
5. **One keypair and one tag per product.** Never reuse `issuer.key` across apps.
6. **Protect the binary.** Pack or obfuscate it (VMProtect, Themida), strip symbols, encrypt strings, Authenticode-sign it, and add self-integrity checks, for example a hash of `kPub` verified from more than one place.
7. **Protect the private keys.** A passphrase (PBKDF2 plus AES), DPAPI, or a hardware token such as a YubiKey. Keep an offline backup, because a lost key means no new licenses.
8. **Stronger binding with the TPM.** Create a non-exportable key in the TPM (CNG "Microsoft Platform Crypto Provider") and wrap `K` to its public key. A different PC cannot unwrap it, and spoofing hardware IDs no longer helps. This is the only way to make the binding truly unspoofable.
9. **Revocation without a server.** Put a serial number in each license and let the app read an owner-signed revocation list file that you hand out. Short expiries with renewals also bound the damage of a leaked key.
10. **If you can host one small thing,** an activation counter (one key, N machines) is the only way to actually detect sharing.

### Releasing

- Attach the three exes from `Release/` to a GitHub Release. Say plainly that the released `ExampleShippedApp.exe` only accepts the demo test key.
- Do not run `Release/PrivateOwnerApp.exe` in place: its first run writes the key files next to it. Run the copy in `PrivateOwnerApp/`.
- Unsigned exes trigger SmartScreen warnings. Authenticode-sign your own builds.
- Programs that read hardware IDs and the clipboard can trip antivirus heuristics. Keep the source public so people can check what `MachineCodeTool` does.
- Pick a repository license. None is included here.

### Tested on

- Windows 11, Visual Studio 2022, one PC. The machine code came out identical with and without admin rights (checked with a restricted token on an admin account).
- Not tested: Windows 10, virtual machines, a second physical PC, Visual Studio 2019, high-DPI scaling.

---

## Pros and cons

### Pros

- **No server.** No hosting, no uptime, no monthly cost, nothing to hack or take down.
- **Works offline and forever.** The shipped app never makes a network call, and needs no updates.
- **Unforgeable keys.** Without your private key, nobody can create a key or alter one (any change breaks the signature).
- **Machine-bound.** A shared key does nothing on another PC, with no tracking needed.
- **Forgiving binding.** 3-of-4 matching survives a new disk, a Windows reinstall, or cloned images.
- **Optional expiry** with clock-rollback protection and live re-checks.
- **Tiny and dependency-free.** About 200 KB, static build, only Windows built-ins, small readable source.
- **Key-loss safety net.** A spare signing key is built in from day one.
- **Simple owner workflow.** One GUI, live feedback on the machine code, an issue log.
- **Weak-binding failsafes.** Weak machine codes are refused unless you explicitly override, and then only with an expiry.
- **Test keys in one click.** A time-limited key anyone can try, with no machine code needed.
- **Fail-quiet.** A bad key shows no error message for a cracker to search for.

### Cons

- **Offline checks can be patched.** A skilled attacker can edit the exe to skip the check or swap in their own public key. Anything the app does not truly *need* a valid license for stays open. (The demo calculator is a plain example of this.) A packer such as VMProtect or Themida is not included.
- **No revocation.** A key stays valid until it expires. If `issuer.key` leaks, you cannot invalidate it without shipping a new build, and this design assumes you never/rarely update.
- **Sharing is prevented, not detected.** You cannot see that a key was passed around, and some sharing routes remain (remote desktop into the buyer's PC, cloned VMs, shared memory dumps, a buyer who tells a friend their real hardware IDs (still difficult to create the working key from it)).
- **Manual issuing.** The buyer must send a machine code first, so store checkouts (Gumroad, itch, etc.) cannot hand out keys automatically.
- **The machine code is sensitive.** It contains the secret half of the ID hashes, so do not post it publicly.
- **Hardware changes mean reissues.** Changing two or more of the four IDs at once needs a new key, and you are the support desk.
- **Weak on bare-bones machines.** VMs and cheap boards that hide SMBIOS values leave fewer than 3 usable IDs. The owner app gates these (see above), but a weak key is still easier to spoof and breaks if either remaining ID changes.
- **Spoofable by experts.** A kernel-level spoofer can fake firmware and disk IDs.
- **Clock-rollback guard is not absolute.** Deleting both stored last-seen values defeats it.
- **Private keys sit in plaintext files.** Offline backup discipline is on you, and losing `issuer.key`/`spare.key` or `asset.key` means no new licenses, ever.
- **Windows only.** It depends on CNG, the registry, SMBIOS tables and Win32.
- **Duplicated fingerprint block.** Each C++ file carries its own copy so it stands alone, and the two must be kept identical by hand.
- **Test keys work on any PC.** By design, and an expiry is enforced. The shipped app contains that code path (`have == 0` in `LicenseOk`). It can only be exercised with a key signed by your private key, so it adds no hole unless you issue one, but delete the branch if you never want it.

### Not included (on purpose)

A server or online activation, TPM binding, a packer or obfuscation, key passphrases, and a revocation list. TPM binding is the only way to make a machine ID truly unspoofable, and it was left out as too heavy for this demo.

---

## Before you ship something real

1. Delete the demo `.key` files and `public.txt`, run `PrivateOwnerApp` to generate your own, paste the new rows into `kPub`, rebuild `ExampleShippedApp`, and keep `spare.key` and `asset.key` backed up **offline**. This invalidates the test key at the top of this README: make a new one and update it.
2. Change the product tag (`Tag` in `PrivateOwnerApp.cs` and `kTag` in `ExampleShippedApp.cpp`) to match your app.
3. Make your app genuinely depend on `gK` (decrypt a needed asset with it), and read [Making it stronger](#making-it-stronger).
4. Pack the final exe, and ship **only** the shipped app (and `MachineCodeTool` if you want it). Never ship `PrivateOwnerApp` or any `.key` file.
