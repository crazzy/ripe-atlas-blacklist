#!/usr/bin/env python

import json
from datetime import datetime, timedelta
from ripe.atlas.cousteau import ProbeRequest, AtlasResultsRequest

output_filename = "data.json"

# Implemented mostly for testing purposes,
# but it is better to identify the individual probes.
country_filter = [
]


# These are all manually discovered to be located in a network
# that will hijack DNS queries and falsify the response.
# The measurement was configured to directly query 9.9.9.9
# but got a response from a totally different DNS server
manual_dnshijack = [
    53600,
    10540,
    55499,
    17822,
    1001549,
    18114,
    11992,
    19195,
    18114,
    1003780,
    20001,
    19195,
    53326,
    30041,
    4290,
    17830,
    54724,
    12681,
    19700,
    52914,
    14843,
    53200,
    1003302,
    55346,
    54441,
    26261,
    54271,
    53379,
    53920,
    50348,
]


def handle_api_response(probes, reason):
    global output
    for p in probes:
        output.append({'id': p['id'], 'reason': reason})


if __name__ == '__main__':
    # Handle the lists configured above
    output = []
    for i in manual_dnshijack:
        output.append({'id': i, 'reason': 'dnshijack'})
    for cc in country_filter:
        filters = {"country_code": cc}
        probes = ProbeRequest(**filters)
        handle_api_response(probes, cc)

    # Filter out what RIPE themselves consider broken
    # See https://atlas.ripe.net/docs/api/v2/reference/
    # (the "status" values)
    filters = {"status": 0}  # Never connected
    probes = ProbeRequest(**filters)
    handle_api_response(probes, 'never-connected')
    filters = {"status": 2}  # Disconnected
    probes = ProbeRequest(**filters)
    handle_api_response(probes, 'disconnected')
    filters = {"status": 3}  # Abandoned
    probes = ProbeRequest(**filters)
    handle_api_response(probes, 'abandoned')

    # Now we've got this DNS measurement where we look
    # at results where there was a response, so something
    # has answered, but where no data was given, and the
    # target is well known to answer these queries.
    # So something is hijacking DNS queries for the probe.
    #
    # Reasoning for the start and stop dates are that the
    # Atlas measurement we're checking here only runs once
    # every week and we want the latest result available.
    kwargs = {
        'msm_id': 12016241,
        'start': datetime.today() - timedelta(days=7),
        'stop': datetime.today()
    }
    is_success, results = AtlasResultsRequest(**kwargs).create()
    if not is_success:
        raise Exception('Atlas API request failed')
    with open("timed-out.txt", "r") as f:
        timed_out_before = f.read().splitlines()
    timed_out_now = []
    for r in results:
        if 'result' in r and r['result']['ANCOUNT'] == 0:
            # Something responded, but it didn't answer the query which the actual
            # target of the measurement is well known to do, hence query was likely
            # hijacked by something on the network of the probe.
            output.append({'id': r['prb_id'], 'reason': 'dnshijack'})
        elif 'result' in r and r['result']['ANCOUNT'] > 0 and 'answers' not in r['result']:
            # Something responded, claimed to provide an answer by non-zero ANCOUNT
            # but there was actually nothing in the answer section, so the query
            # could be hijacked. There are of course other reasons for this, but in
            # this case, I care about reliable probes so gonna assume hijack.
            output.append({'id': r['prb_id'], 'reason': 'dnshijack'})
        elif 'result' not in r:
            # The measurement failed entirely on this probe, which is strange as
            # the target is very well-connected as it's anycasted from many
            # different locations, with several different transit providers. This
            # is what we would see if there's a Great Firewall filtering traffic
            # for example. But we would also see it if there's temporary issues
            # of some kind. We can't really be sure about anything here. So we'll
            # build a list of probes timing out, but only add them to the
            # exclusion list if they've timed out previously.
            timed_out_now.append(r['prb_id'])
            if str(r['prb_id']) in timed_out_before:
                output.append({'id': r['prb_id'], 'reason': 'timeout'})
    with open("timed-out.txt", "w") as f:
        for line in timed_out_now:
            f.write("{}\n".format(line))

    # Output
    with open(output_filename, "w") as f:
        json.dump(output, f, indent=4, sort_keys=True)
