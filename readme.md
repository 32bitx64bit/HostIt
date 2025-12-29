# HostIt
HostIt is a self-hosted alternative to playit.gg.

## Quick Start

### Prerequisites
- Go 1.24 installed.
- VPS for a Linux server. 
- Ports 7000/7001 (agent control and data listeners), 7002 (dashboard). So ensure these ports are opened and not blocked.

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


