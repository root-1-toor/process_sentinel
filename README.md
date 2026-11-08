<div align="center">PROCESS SENTINEL
Trace the process. Find the launcher. Prove the fix.
Hands-on Linux incident response labs built with Docker, Bash, Python, and deliberately vulnerable configurations.

Linux · Docker / Compose · Process Forensics · Persistence Analysis · Incident Response
</div>What is Process Sentinel?
Process Sentinel is a collection of isolated, reproducible security scenarios focused on what happens after suspicious activity appears on a Linux system. Each incident is approached from a defender's perspective: inspect running processes and logs, trace execution paths, distinguish legitimate services from unauthorized behavior, contain the issue, and verify the outcome.

The emphasis is on evidence over assumptions. A disappearing PID is not proof of remediation. A running container is not proof that its application is healthy. And a deleted executable may still have a configured launcher waiting to call it.
Lab boundary: All scenarios are synthetic and intended for local, disposable Docker environments. No real customer data, real adversary, or confirmed production compromise is involved.

Incident index
Incident	Case	Investigation focus	Verified result
01	Gateway	SSH events, account privileges, process ownership, Linux/Docker boundaries	Investigation and process-control experimentation; full account-containment checklist not documented
02	The Returning Process	Parent-child process trees, startup execution, cron persistence	Recurring worker traced and contained in the live container; rebuild durability not established
03	The Ghost Service	Signals (SIGSTOP, SIGTERM), process ancestry, container lifecycle	Process and container shutdown behavior characterized; persistent fix not demonstrated
04	Cold Cache	Monitoring JSON, shell wrapper, file lock, Python worker, rebuild verification	Worker/launcher removed, task disabled, fresh container healthy at /health


Repository layout: The incident links below assume the corresponding folders have been added to this repository. The first three folders match the packaged lab archive; Incident 04 is listed separately so it can be added from the completed VM project.

[01 — Gateway](./incident-01-gateway/)
A Linux gateway records failed and successful SSH authentication, a restricted sudo action, and activity under a test account. Investigate who authenticated, what privileges they had, and where a background process actually lives across the host/container boundary.

Tools: OpenSSH, ps, pstree, sudo, lsof, Docker.
[02 — The Returning Process](./incident-02-returning-process/)
An unobtrusively named process keeps appearing after termination. Follow its ancestry to distinguish an individual worker from the mechanism responsible for launching it. Confirm why killing an instance does not disable a cron schedule or a startup path.

Tools: ps --forest, cron, shell scripting, pkill, Docker inspection.
[03 — The Ghost Service](./incident-03-ghost-service/)
A recurring agent creates a growing process tree. Experiment with pausing and terminating selected processes, and observe how stopping a container's main process differs from removing a background task's launch mechanism.

Tools: htop, pstree, Linux signals, cron, Docker events and logs.
04 — Cold Cache
A monitoring task with a routine-sounding name is found accessing synthetic account data and writing repeated local checkpoint records. Trace the chain from monitoring configuration to wrapper, lock, and worker. Remove the unwanted behavior at the source, rebuild the image, and verify that the legitimate gateway remains responsive.

Tools: Python, JSON, Bash, flock, Docker Compose, curl.

Observed post-rebuild checks: task configured with "enabled": false; checkpoint process absent in ps -efww; gateway returned {"service":"edge-gateway","status":"ok",...} from /health.
Architecture and isolation
Each case runs in its own Compose project. Incidents are not intended to share live state or interfere with one another.
Linux host / VM
└── Docker Engine
    ├── Incident 01: gateway + probe
    ├── Incident 02: target + probe
    ├── Incident 03: gateway
    └── Incident 04: gateway API + monitor + scheduled jobs
The labs use disposable containers and isolated Docker networking where configured. Check the Compose file for each case before launching it; do not assume these exercises are hardened production deployments.
Quick start
Requirements: Linux with Docker Engine and Docker Compose. Some incident folders use the docker-compose (hyphenated) CLI; modern Docker installations can often substitute docker compose.

Clone the repository:
git clone https://github.com/root-1-toor/process_sentinel.git
cd process_sentinel
Run one case at a time from its own directory, for example:
cd incident-02-returning-process
docker-compose up -d --build
docker-compose ps
Observe the target:
docker-compose exec target ps -eo pid,ppid,user,stat,etime,args --forest
When finished, stop only that case:
docker-compose down
Incident 01 uses compose.yaml; depending on the local Compose version, invoke docker compose instead. Incident 04 should be started from its own incident-04/ directory after you add the VM source files to the repository.

Investigation workflow
01 / Establish a baseline — Identify the container, its main process, its services, and the expected behavior before sending signals or changing files.

02 / Collect evidence — Preserve logs, process listings, parent PIDs, configuration, and relevant file metadata. Use each case's evidence/ folder for sanitized artifacts.

03 / Trace execution — Follow the suspicious process upward to its creator and outward to its startup files, schedules, supervisors, or configuration.

04 / Contain precisely — Interrupt the unwanted behavior without assuming a broad pkill, daemon shutdown, or container stop is an acceptable fix.

05 / Remediate at the source — Remove or disable the responsible launch path in source-controlled configuration, not only in a live container's writable layer.

06 / Rebuild and verify — Recreate the environment and test both the absence of the unwanted activity and the continued health of legitimate services.
Practical lessons
- PID namespaces matter. Container PIDs and host PIDs can differ; scope commands to the intended environment.
- A child process is not its launcher. Removing a worker does not necessarily eliminate the mechanism that creates it.
- A lock file is not persistence by itself. flock coordinates execution; inspect who invokes it and what it invokes.
- Exit 137 needs context. It indicates SIGKILL-related termination, not automatically an out-of-memory kill.
- Container uptime is not service health. Verify the actual application endpoint when one exists.
- Durability requires a rebuild test. Changes in the running container can vanish when it is recreated.
- Preserve uncertainty. Distinguish observed evidence from explanations that have not been proven.
Evidence and reporting
Each incident is intended to contain a README and an evidence/ directory. A defensible write-up should include:
- Timeline: observations, commands, and timestamps.
- Indicators: process name, owner, executable path, parent process, and relevant configuration.
- Root cause: the specific mechanism enabling unwanted execution.
- Response: what changed and why.
- Verification: before/after process state, rebuild results, and application health.
- Limitations: anything not verified or collected.
Never commit credentials, secrets, personal data, or unsanitized production logs. The data used in these exercises is synthetic.
Project status
These are investigative training labs, not a commercial EDR or a production intrusion-detection platform. The value is in the reproducible environments, analysis workflow, and evidence-based remediation.

Incident 04 achieved the most complete end-to-end demonstration: inspection → execution-chain reconstruction → source/configuration remediation → image rebuild → application verification. The first three cases remain available as focused investigations and signal/process exercises, with documented limitations.
<div align="center">PROCESS SENTINEL
Don't just kill the process. Understand why it exists.
</div>
