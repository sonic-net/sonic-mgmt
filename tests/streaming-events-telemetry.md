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

1) Have a gNMI tool in host
