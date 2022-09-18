# Overview
The goal is to test the events system from publishing end point to external receiving endpopint that tests every supported event which includes validation against the schema.

# Scope
This system is platform independent. This can be run on a fully configured & functioning SONiC system. As this involves BGP & Interface startup shutdown, require system with established BGP sessions.

# Test bed
Any testbed with couple of established BGP sessions.

# Setup configuration
Require: Few established BGP sessions and all *expected* dockers running.

# Test
This test will simulate scenarios to get the event fired and verify the fired event. It would also simulate scenarios for event system modules down, and verify the behavior.

# Test - Events validation
The following is done for every event declared in src/sonic-yang-models/yang-events

1) Build a gNMI client tool (Go is easier) as part of SONiC-gNMI.
2) Let the tool take arguments as with default values for all.
   * list of keys of interest (key = <Yang nodule>:<Yang container>"); default: any/all
   * Count of events to receive. def: Receive until SIGHUP signal
   * o/p file to receive the events; def: No events written
   * receive timeout -- default: no timeout
   * Use cache -- default: false
   * heartbeat duration -- Default: no heartbeat
3) Tool writes received event as list pf JSON entries.
   [ 
      { 
        "event_str": <...>,
        "missed": <cnt>,
        "timestamp": < timestamp>
      },
      ...
  ]
4) Tools spew total count of received events into STDOUT, during exit.
 
5) The tool exits upon any of the following:
   * Failed to receive/subscribe.
   * Any other internal failure.
   * Received expected count of events
   * Received SIGHUP signal.
  
5) This tool can be copied into host from telemetry docker.

## For events that can be simulated
For each event</br>
   * A function is written to simulate the event and as well revert the simulation.
   * For certain events, might need to run some commands from connected switches -- e.g. BGP Notifications
   * For certain events, which may happen periodically, simulation may just simply pause for required time.
   * Write the list of expected events in the same format as event-receiver tool's JSON list
   * Run the receive client with expected keys & count and o/p file.
   * Pause a second to ensure the client has established subscriber connection.
   * Kick off simulation; Pause a second or more depending on how long the simulation take to result in event publish. 
   * Event publish API itself would take about 100ms to reliably reach the receiver.
   * If receiver not done, stop the receiver via SIGHUP.
   * Open the received o/p as JSON object, which should be a JSON list.
   * Compare the list against the expected.
  
## For kernel events that can *NOT* be simulated
   e.g. "kernel.*write failed" 
1) Scan kernel code in open source for event strings validation
    * List the versions of scanned kernels in the test code.
    * At run time verify current version against this list.
    * Fail if this version is not listed. Suggest steps to validate & fix by adding the version to the list.
  
2) Using logger write logs as kernel would do and verify fired event
   Use steps above to capture & analyze the event.
  
## Events storming.
1) Stop all containers except eventd & database and monit to get the max CPU power
2) Have a receiver running for all events with no count limit.
3) Write a publish tool that can use 30 threads and all 30 publish to get the max rate of 100K events/second for 5 seconds.
4) Pause for 3 seconds for async draining to complete.
5) Stop the tool via SIGHUP
6) Verify the count and validity of event.
  
## Events caching
1) Create expected o/p file of events with N events (say N = 20) in the same format as our receiver tool.
2) To get controlled atmosphere, stop all containers except eventd & database and monit 
3) Restart eventd to get clean state. Pause for a second for service stabilization.
4) Call events-publisher tool or directly via events API to publish M events (M < N).
5) Start the receiver tool with use-cache set to true.
6) Publish the remainder of events (N-M)
7) Verify the o/p file.

### Events caching overflow
1) Repeat the above with variations as below.
   * Use a single event to publish repeatedly.
   * Set M = <Max cache size> + 10.
   * Add a pause of 10ms between two publish to *ensure* that indeed every event is received and any drop is done by eventd *only*.
2) Start the receiver tool with a timeout and no o/p file. The file writing could become a blocker, otherwise.
4) Wait for tool to exit via receive timeout.
5) If tool would not exit after N seconds (need to assess N), send SIGHUP to receiver.
6) Check the receiver tool o/p to be M
  
                                                                                 
## Heartbeat
1) Start receiver tool to with heartbeat duration set to 1 sec and set it to receive only heartbeat events into a o/p file
2) Sleep for N+2 seconds
3) Send SIGHUP to stop the tool
4) Expect N heartbeat events in o/p file.
  
## Stats
1) In each of the above test, add expected stats value 
2) Clean 
