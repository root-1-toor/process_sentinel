IN THE WORDS OF MY ADVANCED AI INCIDIENT RESPONSE SIMULATED INTERVIEWERER


Process Sentinel — Complete Incident Review
November 7–8, 2026 | Four cybersecurity investigations | Linux, Docker, process analysis, persistence, and incident response

You've now worked through four progressively different incident-response exercises. What makes them worth documenting isn't simply that you stopped processes. It's that you moved from identifying suspicious activity to understanding why it existed, who or what controlled it, how it could return, and how to verify that a remediation actually worked.

I'm going to separate what you demonstrably accomplished from what the exercises were designed to test. That matters if you eventually use this work in a GitHub portfolio or describe it during a technical interview.
Executive overview
Incident	Scenario	Primary challenge	Recorded outcome
01 — Gateway	Suspicious SSH authentication and activity under a test account	Access investigation, permissions, Linux process ownership	Investigation and process-level experimentation; full original containment checklist not independently verified
02 — The Returning Process	Disguised background activity repeatedly returns after termination	Process trees, cron persistence, host/container boundaries	Live persistence mechanism identified and contained
03 — The Ghost Service	A recurring service appears to survive process-level intervention	Signals, parent-child relationships, Docker lifecycle	Process-control behavior demonstrated; durable remediation not established
04 — Cold Cache	A routine-sounding monitoring job accesses simulated customer-account data	Multi-file execution chain, config remediation, rebuild verification	Source-level remediation and healthy application confirmed after rebuild

These were isolated, simulated security incidents, not confirmed intrusions into a production system. The record includes an early masquerading-process exercise alongside the Gateway work; I'll account for that within the chronology rather than present it as a fifth completed incident.

Incident 01 — Gateway
Foundational investigation
Authentication • Privileges • Process ownership

1. The scenario
The first investigation involved a small Linux gateway reporting unusual authentication activity.

You were placed in the defender's position, with a Debian-based target running OpenSSH and a separate probe container capable of generating controlled authentication events.

The suspected activity included failed SSH authentication attempts, a successful login, limited privilege use, and background execution under a test account.

The assignment was to reconstruct what happened rather than assume that every unexpected process was malicious.
2. The environment
Incident 01 architecture

The setup used real Linux mechanisms rather than fabricated log entries. The target generated genuine OpenSSH and sudo records.

The relevant account was operator, with deliberately restricted privilege escalation. Its configured passwordless sudo allowance was limited to /usr/bin/id, which reveals identity information but does not provide an unrestricted root shell.

Your primary evidence locations included:
/var/log/sshd.log
/var/log/sudo.log


3. What you investigated
The original mission required you to identify the source and number of failed password attempts, determine which account eventually authenticated, review any sudo activity, identify the background process and its owner, and contain the account.

Your preserved terminal work also shows a substantial exploration of running processes and Linux process visibility.

You used commands such as:
ps aux
ps -u operator -o pid,ppid,user,stat,args --forest
pstree -p
lsof


One of the more interesting process patterns you encountered was:
operator  bash -c while true; do sleep 600 & wait $!; sleep 2; done
              └── sleep 600


You observed multiple versions of that loop, including process IDs 7394 and 6466.

This was an early introduction to a recurring theme across the exercises: the visible sleep process is not necessarily the process controlling the behavior.
4. The namespace and permission confusion
During your investigation, you tried sending signals to process IDs visible through Docker's internal process listings.

For example:
kill 7394
sudo kill 7394
kill -9 7394


From the surrounding Linux environment, some commands returned No such process, even though the PIDs appeared in docker compose exec target ps.

You also encountered Operation not permitted when attempting to signal processes without sufficient permissions.

Those failures exposed two separate problems:
- A PID reported inside a Docker container does not necessarily identify the same process in the host's PID namespace.
- Even when a process is correctly identified, Linux ownership and capability checks determine whether you may signal it.
You explored switching into the target container and examining process relationships there rather than relying exclusively on the host's view.
5. What you learned
This first exercise introduced several important distinctions.

Authentication versus authorization: Successfully logging in as operator was not equivalent to having unrestricted administrative permissions.

Process ownership versus process visibility: Seeing a process ID doesn't automatically mean the current shell can control that process.

Child processes versus controlling processes: Removing a sleep child can leave the parent loop intact.

Container root versus host root: Root access inside a container is not interchangeable with root access in every surrounding environment.
6. Outcome and limitations
The available logs support a substantial investigation of the gateway's process environment and hands-on experimentation with permissions and process control.

I can also reconstruct the intended SSH and sudo investigation from the original lab instructions. However, I don't have a complete verified record showing that all five original mission objectives were satisfied, particularly the final account-locking and failed-login verification.

That doesn't erase the work you did. It means the accurate report should distinguish investigation performed from containment conclusively demonstrated.

The main accomplishment here was building familiarity with the boundary between a Linux process, the account that owns it, and the environment in which its PID is meaningful.

Incident 02 — The Returning Process
Persistence investigation
Cron • Process lineage • Runtime containment

1. The scenario
Incident 02 introduced a background process that repeatedly reappeared.

The simulated gateway was performing apparently normal functions, including SSH access and scheduled maintenance, but an unobtrusive process called .system-metrics kept running under the operator account.

The name suggested routine system telemetry. The actual executable was a shell script that repeatedly invoked sleep 60.

Your objective was to determine why it existed, identify its source, stop the unwanted activity, and establish whether it would return.
2. What made the incident different
Unlike the first incident, terminating a process wasn't sufficient.

The target had two separate mechanisms for launching .system-metrics:
- A startup script, gateway-start.sh, launched an instance when the container initialized.
- A cron entry, /etc/cron.d/system-metrics, launched an additional instance every minute.
The executable itself was located at:
/usr/local/bin/.system-metrics


Its behavior was deliberately simple:
#!/bin/sh
while true; do
    sleep 60
done


But the combination of an infinite loop and repeated cron launches caused processes to accumulate.
3. Your process-tree investigation
You used both host-side pstree and container-side ps --forest to examine the processes.

The resulting hierarchy showed the difference between startup execution and cron execution.
Incident 02 — simplified process tree
containerd-shim
└── sshd (container PID 1)
    ├── .system-metrics
    │   └── sleep 60
    │
    └── cron
        ├── CRON
        │   └── .system-metrics
        │       └── sleep 60
        ├── CRON
        │   └── .system-metrics
        │       └── sleep 60
        └── ...


The diagram combines the host-level and container-level views for clarity. Actual intermediate shell processes are omitted.
Your logs captured the accumulation.

At approximately 9 minutes and 33 seconds of container uptime, the target had ten cron-launched .system-metrics instances plus the startup-launched instance.

A later observation, at approximately 11 minutes and 56 seconds, showed twelve cron-launched instances.

That provided direct evidence that the process population was increasing over time.
4. Your investigation of Docker's runtime
You also went beyond the suspicious processes and explored Docker's own process hierarchy.

This included examining containerd-shim-runc-v2, the container's main process, and the separate probe container.

In one experiment, you targeted PID 13763, the probe's sleep infinity process, and then PID 13741, associated with the probe's shim.

Your Docker inspection eventually reported:
Name=/processsentinel_probe_1
Running=false
Exit=137
OOM=false


Meanwhile, the target remained running.

This was important because it demonstrated that one container could terminate without automatically bringing down another container in the Compose application.

You also learned not to equate a stopped container with evidence that the underlying persistence mechanism had been removed.
5. The decisive test: killing the process wasn't enough
You then ran:
sudo pkill -f .system-metrics


The immediate process tree changed.

Instead of the .system-metrics shells, you briefly observed orphaned sleep 60 children reparented to PID 1.

But when you inspected the process tree again, another .system-metrics instance had appeared.

The new lineage included:
cron
└── CRON
    └── sh
        └── .system-metrics
            └── sleep 60


This was your evidence that terminating the running processes did not disable their source.

The system still had an active scheduling mechanism capable of launching a replacement.
6. Your search for the persistence mechanism
You initially searched the Ubuntu host:
sudo crontab -u operator -l
sudo grep -rn ".system-metrics" /etc/cron*


The host reported that operator was an unknown user, and the host's cron search found nothing.

That wasn't because the evidence was nonexistent. You were looking in the wrong filesystem and user database.

You then correctly moved the investigation inside the container:
docker exec processsentinel_target_1 \
  grep -rn ".system-metrics" /etc/cron* /var/spool/cron/


That exposed the exact persistence entry:
* * * * * operator /usr/local/bin/.system-metrics >/dev/null 2>&1


You had now tied the suspicious process to a specific file and a specific scheduled execution policy.
7. Your live remediation
You executed:
docker exec processsentinel_target_1 pkill -u operator

docker exec processsentinel_target_1 \
  rm /etc/cron.d/system-metrics

docker exec processsentinel_target_1 \
  rm /usr/local/bin/.system-metrics

docker exec processsentinel_target_1 pkill -u operator


Your final process tree showed only the gateway's primary SSH daemon and cron daemon, with no remaining .system-metrics instances.

That was a successful demonstration of live containment.
8. What remained unresolved
The changes were made inside the running container.

The Docker image's source files still contained the original launch mechanisms, including the startup script and cron configuration.

Consequently, a clean rebuild using that unchanged source could have reintroduced the behavior.

This became an important lesson in the next incidents: removing a problem from a running container is not necessarily the same as removing it from the image that creates the container.
9. What Incident 02 demonstrated
Your strongest result wasn't the pkill command. It was the sequence:
1. Observe many instances of an apparently routine process.
2. Trace their owners and parent processes.
3. Terminate running instances.
4. Observe the process return.
5. Find the cron entry responsible for recreation.
6. Remove the active scheduling instruction and executable.
7. Verify their absence from the running process tree.

This was your first clear transition from process termination to persistence investigation.

Incident 03 — The Ghost Service
Process control
Signals • Parent processes • Container shutdown

1. The scenario
Incident 03 was presented as a background service that appeared to behave normally but repeatedly returned after being stopped.

A containerized gateway ran a Python-independent shell-based worker named gateway-agent, with a cron mechanism that launched additional instances.

The exercise was intended to require you to distinguish the legitimate gateway from recurring background activity.

In practice, you found the relevant process relationships quickly. The lab was simpler than its original advanced label suggested.
2. The technical setup
The target was a Debian-based container with OpenSSH and cron.

The background agent repeatedly executed a small synthetic workload and then slept.

The recurring job was configured through:
/etc/cron.d/gateway-maintenance


The job launched:
/usr/local/libexec/gateway-agent


Your Ubuntu-host process tree showed a structure similar to:
containerd-shim (16887)
└── sshd (16908)
    └── cron (16991)
        ├── cron → sh → gateway-agent → sleep
        ├── cron → sh → gateway-agent → sleep
        ├── cron → sh → gateway-agent → sleep
        └── ...


Unlike Incident 02, you moved almost immediately toward experimenting with controlling parent processes.
3. Your signal experiments
You entered a root shell on the Ubuntu VM and experimented with SIGSTOP.

At first, you attempted:
sigstop
sudo sigstop


Those failed because sigstop isn't a standalone command in your shell.

You then used the correct signal-sending syntax:
kill -sigstop 17302
kill -sigstop 17388


In your process tree:
- PID 17302 was a gateway-agent process.
- PID 17388 was an intermediate cron process associated with a different agent instance.
You were exploring the difference between suspending the worker and suspending a process that controlled its execution.

A stopped process generally remains present, but ceases executing until continued.
4. Your approach to the parent-child hierarchy
You correctly recognized that a repeated sleep process was not the root cause of the activity.

The more significant question was which process was responsible for starting new workers.

That led you to inspect cron, shell wrappers, and the container's main process.

Your experiment also revealed a potential danger: the highest visible ancestor is not necessarily an appropriate remediation target.

For example, terminating the container's main SSH daemon would bring down the entire container even though the offending activity originated from a scheduled job.

This distinction became central to Incident 04, where preserving the gateway was an explicit requirement.
5. How the container actually stopped
At one point, you reported that the gateway had exited.

Docker Compose showed:
incident03_gateway_1   Exit 0


Your subsequent inspection returned:
Exit=0
OOM=false
Finished=2026-11-08T12:36:44.941132542Z


The container's SSH log contained the decisive entry:
Received signal 15; terminating.


And Docker's event history recorded:
container die ... exitCode=0


You later clarified what had happened: you had sent SIGTERM from htop yourself, after experimenting with process suspension.

That clarification resolved the otherwise ambiguous shutdown.

The gateway didn't mysteriously disappear because of an unknown attacker or a self-healing mechanism. Your own signal experimentation explained the termination.
6. What you learned about signals
Signal	Meaning	Relevance to your investigation
SIGSTOP	Unconditionally suspends process execution	Used to freeze selected processes
SIGCONT	Resumes a stopped process	Relevant to restoring execution
SIGTERM	Requests process termination	Used through htop during the shutdown
SIGKILL	Forces termination without ordinary signal handling	Explored during the earlier Docker lifecycle experiments

You also saw why it was essential to inspect the process's state, rather than infer everything from its disappearance.

You were no longer simply asking, “Can I kill this process?”

You were asking, “Which process controls the behavior, and what happens to the system when I interfere with that process?”
7. Outcome
The available evidence supports successful experimentation with Linux signals, the process hierarchy, and Docker container lifecycle.

It does not demonstrate permanent removal of the gateway-agent cron job or a successful source-level rebuild after remediation.

In fact, your direct SIGTERM action stopped the gateway itself.

That's a legitimate result of the experiment, but different from completing the intended surgical-remediation objective.
8. Why the exercise felt easy to you
You later said this was the easiest incident so far.

That makes sense in the context of what you had already been doing.

The process tree explicitly displayed the recurring worker beneath cron, so you didn't need to discover a concealed execution chain.

By this stage, you were comfortable using pstree, htop, and signal delivery to explore process control.

The challenge was mainly mechanical. There was comparatively little ambiguity about what was launching the worker.

Incident 03 reinforced process-control concepts, but Incident 04 would require a different kind of investigation entirely.

Incident 04 — Cold Cache
Rebuild verified
Execution-chain analysis • Source remediation • Service availability

1. The scenario
This was your most demanding investigation, taking approximately four hours of hands-on work by your account.

The fictional environment was a production-style edge gateway. Its primary HTTP service appeared functional, and supporting operational processes were running in the background.

The scenario involved unusual local artifacts associated with a background maintenance task.

The challenge was to determine whether the activity was legitimate, locate the execution mechanism, and remove unwanted behavior without disabling the gateway itself.

Unlike the previous incidents, the process tree alone was insufficient to understand what was happening.

You needed to investigate source files, configuration, wrapper scripts, filesystem paths, Docker's image-building behavior, and HTTP service health.
2. The environment
Your project was located at:
~/security-labs/incident-04/


Its structure included:
incident-04/
├── docker-compose.yml
├── Dockerfile
├── README.md
├── config/
│   ├── maintenance.env
│   └── monitors.json
├── gateway/
│   ├── bin/
│   │   ├── gateway-api.py
│   │   └── start-gateway
│   ├── cron/
│   └── ops/
│       ├── checkpoint.py
│       ├── .checkpoint-wrapper.sh
│       ├── housekeeping.sh
│       ├── logrotate-helper.sh
│       └── monitord.py
├── fixtures/
└── evidence/


This differed from the earlier labs because you weren't merely examining processes created by Docker. You were investigating a multi-component application with several layers of configuration and execution.
3. Your first major experiment: stopping the HTTP API
You began by investigating a host-visible Python process:
PID 20051
python3 /opt/gateway/bin/gateway-api.py


You located it with:
ps aux | grep 20051


Then you used htop to interfere with the process.

On a subsequent check, PID 20051 was gone.

You also ran:
pgrep -af 'gateway-api.py'


At that point, no matching process appeared in the host's output.

However, Docker still reported:
incident04_gateway_1   Up


This created an important distinction.

A running Docker container doesn't guarantee that every application inside it is functioning.

The container's PID 1 was the SSH daemon. The HTTP API was a separate process.

Therefore, it was possible to disrupt the HTTP API while leaving the container running.

You later restored or observed the API functioning and verified it through HTTP requests.
4. Understanding the health endpoint
You investigated the API's listening address through its source code:
docker-compose exec gateway grep -rn "8080" /opt/


That revealed:
ThreadingHTTPServer(('127.0.0.1',8080),H).serve_forever()



You also encountered several different HTTP outcomes while testing.
Request	Result	Explanation
127.0.0.0 without a port	Connection failure	Not the intended endpoint
127.0.0.0:8080	Connection failure	Not the address you needed to use
127.0.0.1:8080	HTTP 404	Server reachable, but / was not a defined route
127.0.0.1:8080/health	HTTP 200	Correct application health endpoint

Your working verification command became:
docker-compose exec gateway \
  curl -i --max-time 5 http://127.0.0.1:8080/health


The distinction between 404 and a connection failure mattered.

A 404 response proved the HTTP server was accepting requests. It simply wasn't providing a resource at /.

Ultimately, your correct /health requests returned:
{
  "service": "edge-gateway",
  "status": "ok"
}


The actual responses also included timestamps.
5. Your discovery of the suspicious execution chain
This was the turning point of the incident.

You examined the container's process tree:
docker-compose exec gateway ps -efww


And discovered several active components:
PID 1    sshd
PID 9    monitord.py
PID 11   cron
PID 12   flock
PID 13   checkpoint.py


The specific command behind the lock was:
flock -n /run/.gateway-cache-prime.lock \
  python3 /opt/gateway/ops/checkpoint.py


You recognized that flock was involved, but initially weren't sure whether it was the component responsible for spawning or restarting the worker.

That was a meaningful question.

flock is not itself a monitoring service. It coordinates access to a lock so overlapping processes can be prevented from executing concurrently.

It was part of the execution chain, not necessarily the source of that chain.
6. The suspicious monitor configuration
You then located and inspected:
/etc/gateway/monitors.json


The original configuration contained:
{
  "startup": [
    {
      "id": "gateway-cache-prime",
      "enabled": true,
      "exec": "/opt/gateway/ops/.checkpoint-wrapper.sh"
    }
  ],
  "interval_seconds": 30
}


This was your first clear indication that the activity was being launched deliberately through a configured monitoring mechanism.

The name gateway-cache-prime sounded like routine caching.

But the configuration pointed to a hidden shell wrapper:
/opt/gateway/ops/.checkpoint-wrapper.sh


You immediately questioned why a cache-maintenance operation required that wrapper.

That skepticism proved useful.

A wrapper is not inherently suspicious, but it introduces another execution layer and can obscure the actual command being run if an investigator stops at the service name.
7. The wrapper script
You inspected the wrapper and found:
#!/bin/sh
# avoid parallel copies; lock is held while worker runs
exec flock -n /run/.gateway-cache-prime.lock \
  python3 /opt/gateway/ops/checkpoint.py


That established the wrapper's purpose.

It didn't implement the monitoring policy. It didn't contain the Python worker. It wasn't an independent background supervisor.

It simply passed execution to flock, which in turn launched checkpoint.py.

Your mental model became:
Incident 04 — verified execution chain
Logical execution flow reconstructed from your investigation. It is not a literal PID-by-PID process tree.
8. What checkpoint.py actually did
You inspected the Python source and found the worker's relevant paths:
src = '/srv/fixtures/customer-accounts.csv'out = '/var/tmp/gateway/.checkpoint-stream.jsonl'log = '/var/log/gateway/checkpoint.log'



The script ran continuously.

Every iteration attempted to:
1. Open the simulated customer-account CSV.
2. Read its contents into memory.
3. Calculate the SHA-256 hash of the data.
4. Construct an event labeled export-batch.
5. Append that event to a hidden JSONL file.
6. Write a checkpoint message to a log.
7. Sleep for 11 seconds and repeat.
The source included:
evt = {    'operation': 'export-batch',    'source': src,    'bytes': len(payload),    'sha256': hashlib.sha256(payload).hexdigest(),    'destination': out}



There was no network transmission in the observed script, and the destination received event metadata rather than the full customer records.

So the supported finding was not that real customer information had been exfiltrated.

The supported finding was that a process presented as cache maintenance was repeatedly accessing simulated customer-account records and recording information about that access.

The misleading service name and the data-access behavior did not match.

That was the central suspicious activity in the exercise.
9. Your first remediation attempt
Once you identified the suspicious worker, you navigated to the source directory:
cd ~/security-labs/incident-04/gateway/ops


You used nano to inspect and edit several project files.

You initially removed path variables and imports from checkpoint.py.

That left the worker incomplete, with references to names that were no longer defined.

For example, the modified script still referenced src, out, and log even though those assignments had been deleted.

This would cause runtime errors, although the script's exception handler could continue attempting execution.

You then took a more decisive action:
rm -f ~/security-labs/incident-04/gateway/ops/checkpoint.py

rm -f ~/security-labs/incident-04/gateway/ops/.checkpoint-wrapper.sh


This removed both the actual worker and the shell wrapper from the project source.

That distinction is essential: you were no longer making temporary changes inside a running container.

You had changed the source files used to construct the Docker image.
10. Your first clean rebuild
You stopped the Compose application:
docker-compose down


Then rebuilt it:
docker-compose up -d --build


The build completed successfully.

The Dockerfile included:
COPY gateway/ /opt/gateway/


Because the source directory no longer contained the deleted worker files, the newly created image no longer included them through that copy operation.

You then tested the gateway API again.

The result:
HTTP/1.0 200 OK


followed by JSON identifying the edge-gateway with status: ok.

This established two things:
- The changes survived creation of a new container from the rebuilt image.
- The gateway's HTTP endpoint still functioned afterward.
This was significantly stronger than the runtime-only removal achieved in Incident 02.
11. Verifying which processes remained
You inspected the rebuilt container:
docker-compose exec -T gateway ps -efww


The process tree showed:
PID 1   sshd
PID 7   gateway-api.py
PID 8   monitord.py
PID 10  cron


There were no visible instances of:
checkpoint.py
.checkpoint-wrapper.sh
flock ... checkpoint.py


You also checked:
docker-compose exec -T gateway \
  cat /var/log/gateway/checkpoint.log


The response was:
No such file or directory


This was consistent with the worker not having run after rebuilding.

At this stage, your original remediation was functionally effective against the identified checkpoint execution chain.

Even if the monitor attempted to run the task, the wrapper and worker it depended on had been removed from the new image.
12. The last remaining configuration problem
This led to the final piece of your investigation.

You noticed that the original monitoring configuration still contained:
"enabled": true


and still referenced the deleted wrapper.

You correctly reasoned that deleting the wrapper had already broken that execution chain.

You were right.

A configuration entry pointing to a nonexistent executable cannot successfully launch that executable through the same path.

However, the monitor could still attempt the launch and generate errors, and a later deployment might restore the deleted files.

That made the configuration logically inconsistent with the intended operating state.

You located its source file:
~/security-labs/incident-04/config/monitors.json


You then edited the entry:
{
  "id": "gateway-cache-prime",
  "enabled": false,
  "exec": "/opt/gateway/ops/.checkpoint-wrapper.sh"
}


This was a separate, complementary remediation.

Deleting the files removed the runnable components.

Changing the Boolean removed the monitor's instruction to execute that configured task, assuming the monitor honors its configuration as designed.
13. Your final rebuild and verification
You performed another rebuild, this time explicitly recreating the container:
docker-compose up -d --build --force-recreate


The output included a newly built configuration layer:
Step 5/8 : COPY config/ /etc/gateway/


And Docker successfully recreated:
incident04_gateway_1


You then ran three important verification checks.

Configuration verification
docker-compose exec -T gateway \
  cat /etc/gateway/monitors.json


Result:
"enabled": false


Process verification
docker-compose exec -T gateway ps -efww


Result:
PID 1    sshd
PID 8    gateway-api.py
PID 9    monitord.py
PID 11   cron


No checkpoint worker appeared.

Application verification
docker-compose exec -T gateway \
  curl -fsS http://127.0.0.1:8080/health


Result:
{
  "service": "edge-gateway",
  "status": "ok",
  "time": "2026-11-08T14:23:58.798746+00:00"
}


That's the strongest validation sequence across all four incidents.

You demonstrated that the corrected configuration existed inside the newly created container, the unwanted worker wasn't running at the time of inspection, and the legitimate HTTP application still responded successfully.
14. Final assessment of Incident 04
Incident 04 verification
Passed immediate checks

Control	Observed result
Remove worker source	Completed
Remove wrapper source	Completed
Disable configured launch	Completed
Rebuild image	Completed
Force recreation	Completed
Verify container configuration	Completed
Verify worker absent	Completed
Verify HTTP application healthy	Completed


There are two qualifications worth preserving for an engineering-quality report.

First, the logs do not demonstrate a dedicated long-duration observation period after the final rebuild. The immediate verification is strong, but an extended recurrence test would make the result stronger.

Second, the available record does not include a complete audit of every other maintenance file and potential launch path. Your investigation did establish the identified checkpoint chain, and the final configuration disabled it.

Incident 04 was successfully remediated against the demonstrated mechanism and verified after a clean rebuild.

The progression across your four incidents
Looking at the exercises together, there's a clear progression in the kinds of problems you were solving.
Increasing scope of investigation
01 — Access and process ownership

Foundations




02 — Recurring process and persistence

Multiple launch paths




03 — Signals and container lifecycle

Focused systems experiment




04 — Application-wide remediation

Multi-layer verification




These bars illustrate the breadth of investigation involved, not a standardized industry difficulty score. Incident 03 was less complex than Incident 02 despite its original advanced label.
The eight technical skills you exercised
Skill	Where you demonstrated it
Linux process analysis	ps, pstree, htop, PIDs, PPIDs, ownership
Signal handling	SIGSTOP, SIGTERM, SIGKILL, process termination
Container isolation	Host versus container process IDs and filesystems
Persistence analysis	Scheduled jobs, launchers, recurring processes
Execution-chain tracing	Following a monitor through configuration, wrapper, lock, and worker
Source-code inspection	Shell scripts, Python, and JSON configuration
Docker build and deployment	Editing source, rebuilding images, recreating containers
Operational verification	Process inspection plus HTTP health checks

The biggest conceptual lessons
1. A process is not necessarily the source of its own execution.

That was the defining lesson of Incident 02. You could kill .system-metrics, but cron would start another copy. Removing the visible worker did not automatically eliminate its launcher.

2. A process tree shows relationships, not necessarily intent.

In Incident 03, you could see which processes were spawning children. But knowing the hierarchy didn't automatically identify which intervention would preserve legitimate services.

3. Container liveness is not application health.

Incident 04 demonstrated this directly. Docker could report the gateway as Up even when its separate Python HTTP process was absent. Testing /health gave you application-level evidence that docker-compose ps alone couldn't provide.

4. Docker images and running containers are different operational states.

Incident 02 involved live filesystem changes. Incident 04 went further: you modified project source, rebuilt the image, recreated the container, and inspected the resulting environment.

5. Removing capability and disabling authorization are separate controls.

This was your final realization during Cold Cache.
Remove checkpoint.py
         +
Remove .checkpoint-wrapper.sh
         =
Identified execution chain cannot run as configured

Disable gateway-cache-prime
         =
Monitor should no longer attempt that launch


Your first fix had already broken the execution chain. Disabling the JSON entry made the configuration consistent and added protection against accidentally restoring the removed components.

That wasn't a distinction you needed to take on faith. You reasoned through it yourself.
What I would consider your strongest work
Three moments stand out.

First, in Incident 02, you killed .system-metrics, observed it return, and pursued the recurring launch mechanism rather than continuing to kill individual processes.

Second, in Incident 03, you experimented with stopping and terminating parents and learned firsthand how signal delivery could affect a container's entire lifecycle. It wasn't a flawless containment exercise, but it gave you valuable systems-level observations.

Third, and most importantly, in Incident 04, you went from inspecting a suspicious process to finding the monitor configuration, examining a shell wrapper, reading a Python worker, editing project source, and validating the resulting Docker image.

The third was the most complete investigation-to-remediation sequence.

It required you to connect components that didn't initially look related. You couldn't solve it by identifying a single suspicious PID.
Your incident-response maturity: where you stand
I wouldn't infer a professional seniority level from four guided labs. These exercises were designed environments, and the first three had relatively visible process mechanisms.

But there are concrete observations we can make.

You are increasingly comfortable using Linux processes as evidence, separating runtime behavior from persistent configuration, and testing your assumptions with commands rather than relying on appearances.

You're also beginning to distinguish different standards of success:
Level	What it establishes
Process terminated	A particular running instance stopped
Runtime contained	Identified unwanted behavior is absent from the live environment
Launch mechanism disabled	The known controller can no longer relaunch it
Source remediated	A rebuilt deployment carries the corrective changes
Operationally verified	The legitimate application continues functioning
Forensically documented	Evidence, actions, timestamps, and results are preserved for review

The Cold Cache incident reached the source-remediation and immediate operational-verification stages. Formal evidence packaging and longer-term monitoring remain useful next steps.
Portfolio value
The work is particularly relevant to roles involving backend engineering, platform operations, DevOps, and security-conscious application development.

You can describe it in a portfolio without overstating it:
Process Sentinel — Containerized Linux Incident Response Labs
Built and investigated four isolated, Docker-based Linux security scenarios involving SSH authentication, process masquerading, recurring background jobs, signal handling, and unauthorized simulated data-access activity.

Performed host- and container-level process analysis using ps, pstree, htop, Docker inspection, and Linux signals. Traced recurring process execution to cron schedules, startup scripts, monitoring configurations, shell wrappers, and Python workers.

In the most advanced scenario, identified a maintenance-labeled worker repeatedly accessing synthetic customer-account data. Traced its execution through a JSON-configured monitoring daemon, a shell wrapper, and a file-locking mechanism. Removed the worker and wrapper from the Docker build source, disabled the associated monitoring task, rebuilt and recreated the container, and verified that the unwanted process was absent while the gateway's HTTP health endpoint remained operational.

Key technologies: Linux, Docker, Docker Compose, Bash, Python, JSON, OpenSSH, cron, process namespaces, signal handling, HTTP health checks.

Focus areas: Incident investigation, process lineage, persistence analysis, runtime containment, permanent remediation, and post-deployment verification.
