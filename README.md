# Homelab Dashboard
A simple dashboard for your homelab services with network monitoring capabilities.

## Features
* Displays configured services in groups for easy access.
* Basic network monitoring to show online/offline status of devices on your network.
* Nmap integration for port scanning (optional).
* Password-protected access.
* Light and dark theme support.

## Running the Dashboard

There are two primary ways to run the Homelab Dashboard:

### 1. Using Docker (Recommended)

This is the easiest way to get the dashboard up and running.

**Prerequisites:**

* Docker and Docker Compose installed on your system.

**Steps:**

1.  **Configure `config.yaml`**:
    * Modify the `config.yaml` file (homelab-dashboard/config.yaml) to define your service groups, services, and network monitor settings.
    * **Important**: Generate a bcrypt hash for your desired password and update the `hashedPassword` field in `config.yaml`. You can use an online bcrypt generator or a command-line tool.
2.  **Run with Docker Compose**:
    * Navigate to the `homelab-dashboard` directory where the `docker-compose.yml` file is located.
    * Execute the following command:
        ```bash
        docker-compose up -d
        ```
3.  **Access the Dashboard**:
    * Open your web browser and go to `http://localhost:8080` (or the port you configured in `config.yaml`).

The `docker-compose.yml` file (homelab-dashboard/docker-compose.yml) handles building the Docker image and running the container. It mounts the `config.yaml` file into the container, so changes to the configuration will be reflected after restarting the container. The `NET_ADMIN` and `NET_RAW` capabilities are added to allow the network monitoring tools (like ping and nmap) to function correctly from within the container.

### 2. Running from Console (Go)

**Prerequisites:**

* Go (Golang) installed on your system (version compatible with the project).
* Nmap installed and in your system's PATH (if `nmap_scan_enabled` is true in `config.yaml`).

**Steps:**

1.  **Configure `config.yaml`**:
    * As with the Docker method, ensure `config.yaml` (homelab-dashboard/config.yaml) is correctly set up with your services and a secure `hashedPassword`.
2.  **Navigate to Project Directory**:
    * Open your terminal and go to the `homelab-dashboard` directory.
3.  **Run the Application**:
    * Execute the main Go program:
        ```bash
        go run .
        ```
    * Alternatively, you can build the binary first:
        ```bash
        go build -o homelab-dashboard-app
        ./homelab-dashboard-app
        ```
4.  **Access the Dashboard**:
    * Open your web browser and go to `http://localhost:8080` (or the port specified in `config.yaml`).

The application will load its configuration from `config.yaml` located in the same directory. The `main.go` file (homelab-dashboard/main.go) is the entry point of the application. If network monitoring is enabled (`net_monitor: enable: true` in `config.yaml`), the application will also start the network scanning processes described in `net_monitor.go` (homelab-dashboard/net_monitor.go).

## Configuration

All configuration is done via the `config.yaml` file (homelab-dashboard/config.yaml). Key sections include:

* **`server`**:
    * `port`: The port the dashboard will run on.
    * `username`: Username for basic authentication.
    * `hashedPassword`: Bcrypt hashed password for authentication.
* **`groups`**: An array of service groups, each containing:
    * `name`: Name of the group.
    * `services`: An array of services, each with:
        * `name`: Service name.
        * `url`: URL to the service.
        * `description` (optional): Brief description.
        * `vault_url` (optional): Link to credentials in a password manager.
* **`net_monitor`**: Settings for the network monitoring feature:
    * `enable`: `true` or `false` to enable/disable network monitoring.
    * `default_subnet`: The subnet to scan (e.g., "192.168.1.0/24").
    * `default_interval`: Ping scan interval in seconds.
    * `nmap_scan_enabled`: `true` or `false` to enable nmap port scanning.
    * `nmap_default_interval`: Nmap scan interval in seconds.
    * `nmap_command_args`: Arguments for the nmap command (e.g., "-T4 -F").
    * `nmap_host_timeout`: Timeout in seconds for nmap scan per host.
    * `ping_timeout_ms`: Timeout in milliseconds for individual pings.
