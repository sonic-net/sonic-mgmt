import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class RouteTable:
    def __init__(self, device_handler):
        self.device_handler = device_handler

    def verify_aggregate_routes_generated(self, aggregate_prefixes_list):
        """
        :param aggregate_prefixes_list:
        :return: dictionary with status "Generated" or "NotGenerated" for each prefix
        """
        agg_route_list_gen_status = dict()
        for prefix in aggregate_prefixes_list:
            agg_generated_status = self.device_handler.check_for_aggregate_route_generation(prefix)
            agg_route_list_gen_status[prefix] = agg_generated_status
        return agg_route_list_gen_status
