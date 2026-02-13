# HostIt
HostIt is a high performance self hosted version of similar services such as Playit.gg or Ngrok used to create a tunnel to forward your local projects to the wider web.
Very useful especially in cases where your ISP or router can't do port forwarding, and also provides better security than port forwarding. 

## Quick Start

### Prerequisites
- GO version 1.24.0 (Or greater) needs to be installed.
- VPS for a Linux server (With go installed as well)
- Ports 7000/7001 (agent control and data listeners), 7002 (dashboard). So ensure these ports are opened and not blocked.
- Make sure the respective folders are on the respective machines. Client + Shared for the client, and then server + shared for the server.

### Server (Linux only)
1. cd into the server directory
Then run
   ```sh
   ./build.sh
   ```
2. Start the server. 
   ```sh
   ./server.sh
   ```
3. Open the dashboard (`http://<server-host>:7002`) to finish setup. First start shows the setup wizard, once finished the server has been setup.

4. Optionally, run it as a service, via install-service.sh (Must be ran as sudo)

### Client

#### Linux client
1. cd into the client dictory and run
   ```sh
   ./build.sh
   ```
2. Start the agent launcher script (the dashboard runs on `127.0.0.1:7003` by default):
   ```sh
   ./client.sh
   ```
3. Setup the client with the correct token and server IP.

4. Click "Save + restart agent", it should connect successfully to the server, unless something is misconfigured.

5. Optionally run it as a service, via install-service.sh (must be ran as sudo)
#### Windows client
1. cd into the client dictory and run 
   ```powershell
   .\build.ps1
   ```
2. Run the launcher:
   ```powershell
   .\client.ps1
   ```
3. Setup the client with the correct token and server IP.

4. Click "Save + restart agent", it should connect successfully to the server, unless something is misconfigured.

5. Additional note, windows is considered experimental, and untested. Expect bugs!

## Run in the background (daemon) on Linux

If you launch the server from a SSH, it will close when the SSH tunnel is terminated / closed. If you launch the client from the terminal, and it closes, the client will close.

Use systemd so it keeps running in the background and can auto-restart.

### Server systemd service

- Build once: `cd server && ./build.sh`
- Install + start (requires sudo): `sudo sh ./server/install-service.sh`
- Logs: `journalctl -u hostit-server@$(systemd-escape -p "$(pwd)/server").service -f`
- Stop completely: `sudo systemctl stop hostit-server@$(systemd-escape -p "$(pwd)/server").service`

### Agent systemd service

- Build once: `cd client && ./build.sh`
- Install + start (requires sudo): `sudo sh ./client/install-service.sh`
- Logs: `journalctl -u hostit-agent@$(systemd-escape -p "$(pwd)/client").service -f`
- Stop completely: `sudo systemctl stop hostit-agent@$(systemd-escape -p "$(pwd)/client").service`

### Restart/exit from inside the app

Both dashboards now include **Process → Restart / Exit**.
- When running under systemd, clicking these will terminate the process and systemd will bring it back.
- If not running under systemd, it will just exit.

