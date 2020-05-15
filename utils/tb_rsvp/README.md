Testbed reservation script

two subcommands
reserve and release

reserve option
'-D','--domain       ('Domain name where devices are to be reserved')
'-d','--duration     ('device reservation time, default is 8 hours')
'-t','--topology_id' ('topology id, just a unique string')

the reserve is a blocking call and it is supposed to unblock when
the TB becomes available

release option
-u','--uuid'         (the uuid returned when the TB is reserved)

i.e.
./tb_rsvp_api.py reserve -D GODIVA -t 1
UUID:  4bfff350-5cc8-5c8b-9808-9e4f658702a4

./tb_rsvp_api.py release -u 4bfff350-5cc8-5c8b-9808-9e4f658702a4
<Response [200]>
{
    "ok": true
}

