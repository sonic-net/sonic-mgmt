# Euclid

Euclid is a Python module for configuring telemetry on a switch.
It is composed of two submodules.

The first one is dtel, and it abstracts telemetry on a switch to a set of classes.
One of these is the Switch class, which contains switch-wide attributes,
such as telemetry type (INT Endpoint, INT Transit, Postcard),
latency sensitivity, switch ID, etc. After instantiating a switch,
a user can create related objects such as a report session,
a watchlist or an INT session.

The sonic submodule of euclid extends all classes in the dtel submodule
and extends them to contain all SONiC specific aspects of telemetry configuration.
Upon instantiating a SONiCSwitch (which is a subclass of Switch),
the previous telemetry configuration is wiped (by default),
and the switch is re-configured from scratch. Euclid connects
to the database container on the switch through an unprotected port,
and manipulates ConfigDB by adding, modifying, and deleting keys and values.

All parameters are implemented as Python properties,
so their values are set with simple assignment.
In a typical workflow, a user would start by instantiating a switch:

```python
my_switch = sonic_switch.SONiCSwitch(dtel_switch_id=’123’,
                                     management_ip=’10.10.10.10’,
                                     dtel_monitoring_type='postcard')
```

Then create a report session:

```python
rs = my_switch.create_dtel_report_session(‘192.168.0.1’)
```

Create a watchlist:

```python
wl = my_switch.create_dtel_watchlist('flow')
```

Add entries to the watchlist:

```python
wl.create_entry(priority=10,
                src_ip='10.131.0.0',
                src_ip_mask=11,
                dst_ip='10.131.0.0',
                dst_ip_mask=11,
                dtel_sample_percent=100,
                dtel_report_all=True)
```

Etc.

To use euclid, just import the
module in your python script.
You can find an example configuration script in
switch/ptf-tests/dtel/integration-tests/switch_config_sonic.py.
