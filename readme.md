# HostIt (Playit.gg-style self-hosted tunnel)

HostIt is a self-hosted alternative to playit.gg.
## Quick start

### 1) Start the server (on your VPS)

```fish
cd /home/gavin/Desktop/Playit-prototype/server
./server.sh
```

- Open the dashboard: `http://<vps-ip>:7002/setup` (only available until you create the first user).
- After setup/login, go to **Config** and add at least one **Route**.

Example Minecraft route:
- Name: `minecraft`
- Protocol: `both`
- Public address: `:25565`

If your VPS requires you to open up specific ports, make sure todo so. Importantly 7000, 7001, and 7002.

### 2) Start the agent (on the machine running the service)

```fish
cd /home/gavin/Desktop/Playit-prototype/client
set -x SERVER "<vps-ip>"      # or "<vps-ip>:7000"
set -x TOKEN  "<server-token>"
./client.sh
```

Windows (PowerShell):

```powershell
cd client
$env:SERVER = "<vps-ip>"      # or "<vps-ip>:7000"
$env:TOKEN  = "<server-token>"
\client.ps1
```

If you want a standalone executable on Windows:

```powershell
cd client
\build.ps1
\bin\tunnel-agent.exe -web 127.0.0.1:7003 -server "<vps-ip>" -token "<server-token>"
```

- Agent dashboard: `http://127.0.0.1:7003`
- The agent page has **Start / Stop / Restart** controls and live status updates.
- You can alternatively just start the server and set the token + IP via the GUI.

### 3) Connect from the internet

Congrats, if you can connect from your VPS IP, then you've successfully setup the project.


Additional notes : 
Windows support is considered experimental, and untested. As I don't use Windows. So use at your own risk.

You also need a VPS that runs Linux, so you are required to have some Linux knowledge, and know how to setup a Linux VPS. Lookup tutorials on how todo so. 
