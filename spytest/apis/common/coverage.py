import os
from glob import glob
import inspect
import sys
import pickle
from spytest import st
from spytest import batch
import utilities.common as utils


def generate_msg_coverage_report(consolidated=False, logs_path=None):

    if not st.is_feature_supported("gnmi"):
        return

    look_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../yang/codegen/messages/*/Base/*.py')
    stats = {"all_mods": set(), "used_mods": set(), "total_msg": 0, "used_msg": 0, "total_get": 0, "used_get": 0, "total_create": 0, "used_create": 0, "total_replace": 0, "used_replace": 0, "total_update": 0, "used_update": 0, "total_delete": 0, "used_delete": 0, "total_subscribe": 0, "used_subscribe": 0, "total_create_payload": 0, "used_create_payload": 0, "total_replace_payload": 0, "used_replace_payload": 0, "total_update_payload": 0, "used_update_payload": 0, "total_coverage": 0, "create_coverage": 0, "replace_coverage": 0, "update_coverage": 0, "delete_coverage": 0, "get_coverage": 0, "subscribe_coverage": 0, "msg_coverage": 0, "payload_create_coverage": 0, "payload_replace_coverage": 0, "payload_update_coverage": 0}
    class_stats = {}
    attr_stats = {}
    msg_dict = {}

    def get_logs_path():
        if logs_path:
            return logs_path
        else:
            return st.get_logs_path()

    def get_stats_row(msg_stat_obj, api_type, update_stats=True):
        row = {"create": None, "replace": None, "update": None, "delete": None, "get": None, "payload_create": None, "payload_replace": None, "payload_update": None, "subscribe": None}
        if api_type == "config":
            row = {"create": 0, "replace": 0, "update": 0, "delete": 0, "get": 0, "payload_create": 0, "payload_replace": 0, "payload_update": 0, "subscribe": 0}
            if update_stats:
                msg_stat_obj["total_get"] += 1
                msg_stat_obj["total_create"] += 1
                msg_stat_obj["total_replace"] += 1
                msg_stat_obj["total_update"] += 1
                msg_stat_obj["total_delete"] += 1
                msg_stat_obj["total_subscribe"] += 1
                msg_stat_obj["total_create_payload"] += 1
                msg_stat_obj["total_replace_payload"] += 1
                msg_stat_obj["total_update_payload"] += 1
        else:
            row["get"] = 0
            row["subscribe"] = 0
            if update_stats:
                msg_stat_obj["total_get"] += 1
                msg_stat_obj["total_subscribe"] += 1
        return row

    def init_dynamic_metadata(actual_attr, actual_msg, op):
        if actual_attr not in attr_stats[actual_msg]['all_attrs']:
            attr_stats[actual_msg]["all_attrs"].add(actual_attr)
            attr_stats[actual_msg]["rows"][actual_attr] = {}
            msg_dict[actual_msg]['attrs'][actual_attr] = {'yang_path': actual_attr, 'name': actual_attr}
            msg_dict[actual_msg]['attrs'][actual_attr]['config'] = 'config'
            if op.lower() in ["get", "subscribe"]:
                msg_dict[actual_msg]['attrs'][actual_attr]['config'] = 'state'
            elif op.lower() in ['create', 'update', 'replace', 'delete']:
                msg_dict[actual_msg]['attrs'][actual_attr]['config'] = op.lower()

    def update_stats(op_stats_obj, attr, op):
        if op.lower() == "create":
            op_stats_obj["used_create"] += 1
            op_stats_obj["rows"][attr]["create"] = 1
        if op.lower() == "replace":
            op_stats_obj["used_replace"] += 1
            op_stats_obj["rows"][attr]["replace"] = 1
        if op.lower() == "update":
            op_stats_obj["used_update"] += 1
            op_stats_obj["rows"][attr]["update"] = 1
        if op.lower() == "delete" or op.lower() == "remove":
            op_stats_obj["used_delete"] += 1
            op_stats_obj["rows"][attr]["delete"] = 1
        if op.lower() == "get":
            op_stats_obj["used_get"] += 1
            op_stats_obj["rows"][attr]["get"] = 1
        if op.lower() == "subscribe":
            op_stats_obj["used_subscribe"] += 1
            op_stats_obj["rows"][attr]["subscribe"] = 1
        if op.lower() == "payload_create":
            op_stats_obj["used_create_payload"] += 1
            op_stats_obj["rows"][attr]["payload_create"] = 1
        if op.lower() == "payload_replace":
            op_stats_obj["used_replace_payload"] += 1
            op_stats_obj["rows"][attr]["payload_replace"] = 1
        if op.lower() == "payload_update":
            op_stats_obj["used_update_payload"] += 1
            op_stats_obj["rows"][attr]["payload_update"] = 1

    def add_top_level_data(at_stats, mg_stats):
        for op in mg_stats.keys():
            if mg_stats[op] is not None:
                if op.lower() == "create":
                    if mg_stats[op] == 1:
                        at_stats["used_create"] += 1
                    if mg_stats[op] == 1 or mg_stats[op] == 0:
                        at_stats["total_create"] += 1
                if op.lower() == "replace":
                    if mg_stats[op] == 1:
                        at_stats["used_replace"] += 1
                    if mg_stats[op] == 1 or mg_stats[op] == 0:
                        at_stats["total_replace"] += 1
                if op.lower() == "update":
                    if mg_stats[op] == 1:
                        at_stats["used_update"] += 1
                    if mg_stats[op] == 1 or mg_stats[op] == 0:
                        at_stats["total_update"] += 1
                if op.lower() == "delete" or op.lower() == "remove":
                    if mg_stats[op] == 1:
                        at_stats["used_delete"] += 1
                    if mg_stats[op] == 1 or mg_stats[op] == 0:
                        at_stats["total_delete"] += 1
                if op.lower() == "get":
                    if mg_stats[op] == 1:
                        at_stats["used_get"] += 1
                    if mg_stats[op] == 1 or mg_stats[op] == 0:
                        at_stats["total_get"] += 1
                if op.lower() == "subscribe":
                    if mg_stats[op] == 1:
                        at_stats["used_subscribe"] += 1
                    if mg_stats[op] == 1 or mg_stats[op] == 0:
                        at_stats["total_subscribe"] += 1
                if op.lower() == "payload_create":
                    if mg_stats[op] == 1:
                        at_stats["used_create_payload"] += 1
                    if mg_stats[op] == 1 or mg_stats[op] == 0:
                        at_stats["total_create_payload"] += 1
                if op.lower() == "payload_replace":
                    if mg_stats[op] == 1:
                        at_stats["used_replace_payload"] += 1
                    if mg_stats[op] == 1 or mg_stats[op] == 0:
                        at_stats["total_replace_payload"] += 1
                if op.lower() == "payload_update":
                    if mg_stats[op] == 1:
                        at_stats["used_update_payload"] += 1
                    if mg_stats[op] == 1 or mg_stats[op] == 0:
                        at_stats["total_update_payload"] += 1

    def get_attr_stats_row(attr_data):
        row = ["N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]
        index_map = {
            "get": 0,
            "create": 1,
            "replace": 2,
            "update": 3,
            "delete": 4,
            "subscribe": 5,
            "payload_create": 6,
            "payload_replace": 7,
            "payload_update": 8
        }

        def mark_set(key, index):
            if attr_data[key] is not None:
                if attr_data[key] == 1:
                    row[index] = "Y"
                elif attr_data[key] == "N/A":
                    row[index] = "N/A"
                else:
                    row[index] = "N"
        for key in attr_data.keys():
            mark_set(key, index_map[key])
        return row

    for file in glob(look_dir):
        name = os.path.splitext(os.path.basename(file))[0]
        if name == '__init__':
            continue
        dir_name = os.path.splitext(os.path.dirname(file))[0]
        sys.path.append(dir_name)
        module = __import__(name)
        msgs = inspect.getmembers(sys.modules[module.__name__], inspect.isclass)
        for msg in msgs:
            if msg[0] in ['Base', 'CustomList', 'NorthBoundApi', 'OrderedDict']:
                continue
            else:
                if hasattr(msg[1], 'get_stats_metadata'):
                    meta_data = msg[1].get_stats_metadata()
                    stats["all_mods"].add(meta_data['mod_name'])
                    if meta_data['mod_name'] not in class_stats:
                        class_stats[meta_data['mod_name']] = {"all_classes": set(), "used_classes": set(), "msg_ops": {}, "total_get": 0, "used_get": 0, "total_create": 0, "used_create": 0, "total_replace": 0, "used_replace": 0, "total_update": 0, "used_update": 0, "total_delete": 0, "used_delete": 0, "total_subscribe": 0, "used_subscribe": 0, "total_coverage": 0, "create_coverage": 0, "replace_coverage": 0, "update_coverage": 0, "delete_coverage": 0, "get_coverage": 0, "subscribe_coverage": 0, "payload_create_coverage": 0, "payload_replace_coverage": 0, "payload_update_coverage": 0, "total_create_payload": 0, "used_create_payload": 0, "total_replace_payload": 0, "used_replace_payload": 0, "total_update_payload": 0, "used_update_payload": 0}
                    class_stats[meta_data['mod_name']]["all_classes"].add(meta_data['yang_path'])
                    class_stats[meta_data['mod_name']]["msg_ops"][meta_data['yang_path']] = get_stats_row({}, meta_data["config"], False)
                    msg_dict[meta_data['yang_path']] = meta_data
                    if meta_data['yang_path'] not in attr_stats:
                        attr_stats[meta_data['yang_path']] = {"all_attrs": set(), "used_attrs": set(), "rows": {}, "total_get": 0, "used_get": 0, "total_create": 0, "used_create": 0, "total_replace": 0, "used_replace": 0, "total_update": 0, "used_update": 0, "total_delete": 0, "used_delete": 0, "total_subscribe": 0, "used_subscribe": 0, "total_coverage": 0, "create_coverage": 0, "replace_coverage": 0, "update_coverage": 0, "delete_coverage": 0, "get_coverage": 0, "subscribe_coverage": 0, "payload_create_coverage": 0, "payload_replace_coverage": 0, "payload_update_coverage": 0, "total_create_payload": 0, "used_create_payload": 0, "total_replace_payload": 0, "used_replace_payload": 0, "total_update_payload": 0, "used_update_payload": 0}
                    for attr in meta_data["attrs"]:
                        row = get_stats_row(attr_stats[meta_data['yang_path']], meta_data["attrs"][attr]["config"])
                        attr_stats[meta_data['yang_path']]["rows"][attr] = row
                        attr_stats[meta_data['yang_path']]["all_attrs"].add(attr)
    if not consolidated:
        run_data = st.get_cache("__msg_stats", default={})
    else:
        # get all the result file paths
        prefix = batch.get_node_prefix()
        fmt = "{}/{}*/message_coverage/stats.pkl".format(get_logs_path(), prefix)
        files = glob(fmt)
        run_data = {}
        for pkl_file in files:
            with open(pkl_file, "rb") as pkl_fp:
                # nosemgrep-next-line
                pkl_data = pickle.load(pkl_fp)
                for mod in pkl_data:
                    if mod not in run_data:
                        run_data[mod] = pkl_data[mod]
                    else:
                        for pkl_msg in pkl_data[mod]:
                            if pkl_msg not in run_data[mod]:
                                run_data[mod][pkl_msg] = pkl_data[mod][pkl_msg]
                            else:
                                run_data[mod][pkl_msg]["ops"] = run_data[mod][pkl_msg]["ops"].union(pkl_data[mod][pkl_msg]["ops"])
                                for pkl_attr in pkl_data[mod][pkl_msg]["attrs"]:
                                    if pkl_attr not in run_data[mod][pkl_msg]["attrs"]:
                                        run_data[mod][pkl_msg]["attrs"][pkl_attr] = pkl_data[mod][pkl_msg]["attrs"][pkl_attr]
                                    else:
                                        run_data[mod][pkl_msg]["attrs"][pkl_attr] = run_data[mod][pkl_msg]["attrs"][pkl_attr].union(pkl_data[mod][pkl_msg]["attrs"][pkl_attr])

    # calculate stats
    for mod in run_data:
        stats["used_mods"].add(mod)
        for msg in run_data[mod]:
            class_stats[mod]["used_classes"].add(msg)
            for attr in run_data[mod][msg]["attrs"]:
                if "@@@" in attr:
                    attr_split_data = attr.split("@@@")
                    actual_attr = attr_split_data[0]
                    actual_msg = attr_split_data[1]
                    if actual_msg != msg:
                        class_stats[mod]["msg_ops"][actual_msg]["payload_create"] = 1
                        class_stats[mod]["msg_ops"][actual_msg]["payload_replace"] = 1
                        class_stats[mod]["msg_ops"][actual_msg]["payload_update"] = 1
                else:
                    actual_attr = attr
                    actual_msg = msg
                for op in run_data[mod][msg]["attrs"][attr]:
                    init_dynamic_metadata(actual_attr, actual_msg, op)
                    update_stats(attr_stats[actual_msg], actual_attr, op)
                attr_stats[actual_msg]["used_attrs"].add(actual_attr)
            for op in run_data[mod][msg]["ops"]:
                if op.lower() == "create":
                    class_stats[mod]["msg_ops"][msg]["create"] = 1
                if op.lower() == "replace":
                    class_stats[mod]["msg_ops"][msg]["replace"] = 1
                if op.lower() == "update":
                    class_stats[mod]["msg_ops"][msg]["update"] = 1
                if op.lower() == "delete" or op.lower() == "remove":
                    class_stats[mod]["msg_ops"][msg]["delete"] = 1
                if op.lower() == "get":
                    class_stats[mod]["msg_ops"][msg]["get"] = 1
                if op.lower() == "subscribe":
                    class_stats[mod]["msg_ops"][msg]["subscribe"] = 1

    plod_msg = "<br>(Used in Parent URI)"
    msg_stats_header = ["Messages", "# of Attributes Tested", "GET", "CREATE", "REPLACE", "UPDATE", "DELETE", "SUBSCRIBE", "PAYLOAD-CREATE" + plod_msg, "PAYLOAD-REPLACE" + plod_msg, "PAYLOAD-UPDATE" + plod_msg, "Total Coverage", "GET-Coverage", "CREATE-Coverage", "REPLACE-Coverage", "UPDATE-Coverage", "DELETE-Coverage", "SUBSCRIBE-Coverage", "Payload-Create-Coverage", "Payload-Replace-Coverage", "Payload-Update-Coverage"]
    for mod in sorted(stats["all_mods"]):
        msg_stats_rows = []
        for msg in sorted(class_stats[mod]["all_classes"]):
            attr_stats_header = ["Attributes", "GET", "CREATE", "REPLACE", "UPDATE", "DELETE", "SUBSCRIBE", "PAYLOAD-CREATE" + plod_msg, "PAYLOAD-REPLACE" + plod_msg, "PAYLOAD-UPDATE" + plod_msg, "Total Coverage"]
            attr_stats_row = []
            for attr in sorted(attr_stats[msg]["rows"]):
                row = [msg_dict[msg]["attrs"][attr]['name']]
                row.extend(get_attr_stats_row(attr_stats[msg]["rows"][attr]))
                attr_stats_row.append(row)
            attr_summary = ["RESULT"]
            attr_stats[msg]['get_coverage'] = round(attr_stats[msg]['used_get'] / attr_stats[msg]['total_get'] * 100)
            attr_summary.append(f"{attr_stats[msg]['used_get']}/{attr_stats[msg]['total_get']}({round(attr_stats[msg]['used_get']/attr_stats[msg]['total_get']*100)}%)")
            if attr_stats[msg]['total_create'] > 0:
                attr_stats[msg]['create_coverage'] = round(attr_stats[msg]['used_create'] / attr_stats[msg]['total_create'] * 100)
                attr_summary.append(f"{attr_stats[msg]['used_create']}/{attr_stats[msg]['total_create']}({attr_stats[msg]['create_coverage']}%)")
            else:
                attr_summary.append('N/A')
            if attr_stats[msg]['total_replace'] > 0:
                attr_stats[msg]['replace_coverage'] = round(attr_stats[msg]['used_replace'] / attr_stats[msg]['total_replace'] * 100)
                attr_summary.append(f"{attr_stats[msg]['used_replace']}/{attr_stats[msg]['total_replace']}({attr_stats[msg]['replace_coverage']}%)")
            else:
                attr_summary.append('N/A')
            if attr_stats[msg]['total_update'] > 0:
                attr_stats[msg]['update_coverage'] = round(attr_stats[msg]['used_update'] / attr_stats[msg]['total_update'] * 100)
                attr_summary.append(f"{attr_stats[msg]['used_update']}/{attr_stats[msg]['total_update']}({attr_stats[msg]['update_coverage']}%)")
            else:
                attr_summary.append('N/A')
            if attr_stats[msg]['total_delete'] > 0:
                attr_stats[msg]['delete_coverage'] = round(attr_stats[msg]['used_delete'] / attr_stats[msg]['total_delete'] * 100)
                attr_summary.append(f"{attr_stats[msg]['used_delete']}/{attr_stats[msg]['total_delete']}({attr_stats[msg]['delete_coverage']}%)")
            else:
                attr_summary.append('N/A')
            if attr_stats[msg]['total_subscribe'] > 0:
                attr_stats[msg]['subscribe_coverage'] = round(attr_stats[msg]['used_subscribe'] / attr_stats[msg]['total_subscribe'] * 100)
                attr_summary.append(f"{attr_stats[msg]['used_subscribe']}/{attr_stats[msg]['total_subscribe']}({attr_stats[msg]['subscribe_coverage']}%)")
            else:
                attr_summary.append('N/A')
            if attr_stats[msg]['total_create_payload'] > 0:
                attr_stats[msg]['payload_create_coverage'] = round(attr_stats[msg]['used_create_payload'] / attr_stats[msg]['total_create_payload'] * 100)
                attr_summary.append(f"{attr_stats[msg]['used_create_payload']}/{attr_stats[msg]['total_create_payload']}({attr_stats[msg]['payload_create_coverage']}%)")
            else:
                attr_summary.append('N/A')

            if attr_stats[msg]['total_replace_payload'] > 0:
                attr_stats[msg]['payload_replace_coverage'] = round(attr_stats[msg]['used_replace_payload'] / attr_stats[msg]['total_replace_payload'] * 100)
                attr_summary.append(f"{attr_stats[msg]['used_replace_payload']}/{attr_stats[msg]['total_replace_payload']}({attr_stats[msg]['payload_replace_coverage']}%)")
            else:
                attr_summary.append('N/A')

            if attr_stats[msg]['total_update_payload'] > 0:
                attr_stats[msg]['payload_update_coverage'] = round(attr_stats[msg]['used_update_payload'] / attr_stats[msg]['total_update_payload'] * 100)
                attr_summary.append(f"{attr_stats[msg]['used_update_payload']}/{attr_stats[msg]['total_update_payload']}({attr_stats[msg]['payload_update_coverage']}%)")
            else:
                attr_summary.append('N/A')
            used_coverage = attr_stats[msg]['used_get'] + attr_stats[msg]['used_create'] + attr_stats[msg]['used_replace'] + attr_stats[msg]['used_update'] + attr_stats[msg]['used_delete'] + attr_stats[msg]['used_subscribe'] + attr_stats[msg]['used_update_payload'] + attr_stats[msg]['used_create_payload'] + attr_stats[msg]['used_replace_payload']
            total_coverage = attr_stats[msg]['total_get'] + attr_stats[msg]['total_create'] + attr_stats[msg]['total_replace'] + attr_stats[msg]['total_update'] + attr_stats[msg]['total_delete'] + attr_stats[msg]['total_subscribe'] + attr_stats[msg]['total_update_payload'] + attr_stats[msg]['total_create_payload'] + attr_stats[msg]['total_replace_payload']
            attr_stats[msg]["total_coverage"] = round((used_coverage / total_coverage) * 100)
            attr_summary.append(f"{used_coverage}/{total_coverage}({attr_stats[msg]['total_coverage']}%)")
            attr_stats_row.append(attr_summary)
            filepath = os.path.join(get_logs_path(), "message_coverage", f"{mod}_{msg_dict[msg]['name']}.html")
            utils.write_html_table2(attr_stats_header, attr_stats_row, filepath)
            msg_stats_row = [f"<a href='{mod}_{msg_dict[msg]['name']}.html'>{msg_dict[msg]['name']}</a>", f"{len(attr_stats[msg]['used_attrs'])}/{len(attr_stats[msg]['all_attrs'])}({round(len(attr_stats[msg]['used_attrs'])/len(attr_stats[msg]['all_attrs'])*100)}%)"]
            msg_stats_row.extend(get_attr_stats_row(class_stats[mod]["msg_ops"][msg]))
            msg_line = []
            add_top_level_data(attr_stats[msg], class_stats[mod]["msg_ops"][msg])

            # Re-compute after adding top-level data
            attr_stats[msg]['get_coverage'] = round(attr_stats[msg]['used_get'] / attr_stats[msg]['total_get'] * 100)
            if attr_stats[msg]['total_create'] > 0:
                attr_stats[msg]['create_coverage'] = round(attr_stats[msg]['used_create'] / attr_stats[msg]['total_create'] * 100)
            if attr_stats[msg]['total_replace'] > 0:
                attr_stats[msg]['replace_coverage'] = round(attr_stats[msg]['used_replace'] / attr_stats[msg]['total_replace'] * 100)
            if attr_stats[msg]['total_update'] > 0:
                attr_stats[msg]['update_coverage'] = round(attr_stats[msg]['used_update'] / attr_stats[msg]['total_update'] * 100)
            if attr_stats[msg]['total_delete'] > 0:
                attr_stats[msg]['delete_coverage'] = round(attr_stats[msg]['used_delete'] / attr_stats[msg]['total_delete'] * 100)
            if attr_stats[msg]['total_subscribe'] > 0:
                attr_stats[msg]['subscribe_coverage'] = round(attr_stats[msg]['used_subscribe'] / attr_stats[msg]['total_subscribe'] * 100)
            if attr_stats[msg]['total_create_payload'] > 0:
                attr_stats[msg]['payload_create_coverage'] = round(attr_stats[msg]['used_create_payload'] / attr_stats[msg]['total_create_payload'] * 100)
            if attr_stats[msg]['total_replace_payload'] > 0:
                attr_stats[msg]['payload_replace_coverage'] = round(attr_stats[msg]['used_replace_payload'] / attr_stats[msg]['total_replace_payload'] * 100)
            if attr_stats[msg]['total_update_payload'] > 0:
                attr_stats[msg]['payload_update_coverage'] = round(attr_stats[msg]['used_update_payload'] / attr_stats[msg]['total_update_payload'] * 100)
            used_coverage = attr_stats[msg]['used_get'] + attr_stats[msg]['used_create'] + attr_stats[msg]['used_replace'] + attr_stats[msg]['used_update'] + attr_stats[msg]['used_delete'] + attr_stats[msg]['used_subscribe'] + attr_stats[msg]['used_create_payload'] + attr_stats[msg]['used_replace_payload'] + attr_stats[msg]['used_update_payload']
            total_coverage = attr_stats[msg]['total_get'] + attr_stats[msg]['total_create'] + attr_stats[msg]['total_replace'] + attr_stats[msg]['total_update'] + attr_stats[msg]['total_delete'] + attr_stats[msg]['total_subscribe'] + attr_stats[msg]['total_create_payload'] + attr_stats[msg]['total_replace_payload'] + attr_stats[msg]['total_update_payload']
            attr_stats[msg]["total_coverage"] = round((used_coverage / total_coverage) * 100)

            msg_line.append(f"{used_coverage}/{total_coverage}({attr_stats[msg]['total_coverage']}%)")
            msg_line.append(f"{attr_stats[msg]['used_get']}/{attr_stats[msg]['total_get']}({attr_stats[msg]['get_coverage']}%)")
            msg_line.append(f"{attr_stats[msg]['used_create']}/{attr_stats[msg]['total_create']}({attr_stats[msg]['create_coverage']}%)")
            msg_line.append(f"{attr_stats[msg]['used_replace']}/{attr_stats[msg]['total_replace']}({attr_stats[msg]['replace_coverage']}%)")
            msg_line.append(f"{attr_stats[msg]['used_update']}/{attr_stats[msg]['total_update']}({attr_stats[msg]['update_coverage']}%)")
            msg_line.append(f"{attr_stats[msg]['used_delete']}/{attr_stats[msg]['total_delete']}({attr_stats[msg]['delete_coverage']}%)")
            msg_line.append(f"{attr_stats[msg]['used_subscribe']}/{attr_stats[msg]['total_subscribe']}({attr_stats[msg]['subscribe_coverage']}%)")
            msg_line.append(f"{attr_stats[msg]['used_create_payload']}/{attr_stats[msg]['total_create_payload']}({attr_stats[msg]['payload_create_coverage']}%)")
            msg_line.append(f"{attr_stats[msg]['used_replace_payload']}/{attr_stats[msg]['total_replace_payload']}({attr_stats[msg]['payload_replace_coverage']}%)")
            msg_line.append(f"{attr_stats[msg]['used_update_payload']}/{attr_stats[msg]['total_update_payload']}({attr_stats[msg]['payload_update_coverage']}%)")
            msg_stats_row.extend(msg_line)
            msg_stats_rows.append(msg_stats_row)

            class_stats[mod]["total_get"] += attr_stats[msg]['total_get']
            class_stats[mod]["used_get"] += attr_stats[msg]['used_get']
            if class_stats[mod]["total_get"] > 0:
                class_stats[mod]["get_coverage"] = round(class_stats[mod]["used_get"] / class_stats[mod]["total_get"] * 100)

            class_stats[mod]["total_create"] += attr_stats[msg]['total_create']
            class_stats[mod]["used_create"] += attr_stats[msg]['used_create']
            if class_stats[mod]["total_create"] > 0:
                class_stats[mod]["create_coverage"] = round(class_stats[mod]["used_create"] / class_stats[mod]["total_create"] * 100)

            class_stats[mod]["total_replace"] += attr_stats[msg]['total_replace']
            class_stats[mod]["used_replace"] += attr_stats[msg]['used_replace']
            if class_stats[mod]["total_replace"] > 0:
                class_stats[mod]["replace_coverage"] = round(class_stats[mod]["used_replace"] / class_stats[mod]["total_replace"] * 100)

            class_stats[mod]["total_update"] += attr_stats[msg]['total_update']
            class_stats[mod]["used_update"] += attr_stats[msg]['used_update']
            if class_stats[mod]["total_update"] > 0:
                class_stats[mod]["update_coverage"] = round(class_stats[mod]["used_update"] / class_stats[mod]["total_update"] * 100)

            class_stats[mod]["total_delete"] += attr_stats[msg]['total_delete']
            class_stats[mod]["used_delete"] += attr_stats[msg]['used_delete']
            if class_stats[mod]["total_delete"] > 0:
                class_stats[mod]["delete_coverage"] = round(class_stats[mod]["used_delete"] / class_stats[mod]["total_delete"] * 100)

            class_stats[mod]["total_subscribe"] += attr_stats[msg]['total_subscribe']
            class_stats[mod]["used_subscribe"] += attr_stats[msg]['used_subscribe']
            if class_stats[mod]["total_subscribe"] > 0:
                class_stats[mod]["subscribe_coverage"] = round(class_stats[mod]["used_subscribe"] / class_stats[mod]["total_subscribe"] * 100)

            class_stats[mod]["total_create_payload"] += attr_stats[msg]['total_create_payload']
            class_stats[mod]["used_create_payload"] += attr_stats[msg]['used_create_payload']
            if class_stats[mod]["total_create_payload"] > 0:
                class_stats[mod]["payload_create_coverage"] = round(class_stats[mod]["used_create_payload"] / class_stats[mod]["total_create_payload"] * 100)

            class_stats[mod]["total_replace_payload"] += attr_stats[msg]['total_replace_payload']
            class_stats[mod]["used_replace_payload"] += attr_stats[msg]['used_replace_payload']
            if class_stats[mod]["total_replace_payload"] > 0:
                class_stats[mod]["payload_replace_coverage"] = round(
                    class_stats[mod]["used_replace_payload"] / class_stats[mod]["total_replace_payload"] * 100)

            class_stats[mod]["total_update_payload"] += attr_stats[msg]['total_update_payload']
            class_stats[mod]["used_update_payload"] += attr_stats[msg]['used_update_payload']
            if class_stats[mod]["total_update_payload"] > 0:
                class_stats[mod]["payload_update_coverage"] = round(class_stats[mod]["used_update_payload"] / class_stats[mod]["total_update_payload"] * 100)

        used_coverage = class_stats[mod]['used_get'] + class_stats[mod]['used_create'] + class_stats[mod]['used_replace'] + class_stats[mod]['used_update'] + class_stats[mod]['used_delete'] + class_stats[mod]['used_subscribe'] + class_stats[mod]['used_create_payload'] + class_stats[mod]['used_replace_payload'] + class_stats[mod]['used_update_payload']
        total_coverage = class_stats[mod]['total_get'] + class_stats[mod]['total_create'] + class_stats[mod]['total_replace'] + class_stats[mod]['total_update'] + class_stats[mod]['total_delete'] + class_stats[mod]['total_subscribe'] + class_stats[mod]['total_create_payload'] + class_stats[mod]['total_replace_payload'] + class_stats[mod]['total_update_payload']
        class_stats[mod]["total_coverage"] = round((used_coverage / total_coverage) * 100)
        msg_stats_line = ["RESULT", "", "", "", "", "", "", "", "", "", ""]
        msg_stats_line.append(f"{used_coverage}/{total_coverage}({class_stats[mod]['total_coverage']}%)")
        msg_stats_line.append(f"{class_stats[mod]['used_get']}/{class_stats[mod]['total_get']}({class_stats[mod]['get_coverage']}%)")
        msg_stats_line.append(f"{class_stats[mod]['used_create']}/{class_stats[mod]['total_create']}({class_stats[mod]['create_coverage']}%)")
        msg_stats_line.append(f"{class_stats[mod]['used_replace']}/{class_stats[mod]['total_replace']}({class_stats[mod]['replace_coverage']}%)")
        msg_stats_line.append(f"{class_stats[mod]['used_update']}/{class_stats[mod]['total_update']}({class_stats[mod]['update_coverage']}%)")
        msg_stats_line.append(f"{class_stats[mod]['used_delete']}/{class_stats[mod]['total_delete']}({class_stats[mod]['delete_coverage']}%)")
        msg_stats_line.append(f"{class_stats[mod]['used_subscribe']}/{class_stats[mod]['total_subscribe']}({class_stats[mod]['subscribe_coverage']}%)")
        msg_stats_line.append(f"{class_stats[mod]['used_create_payload']}/{class_stats[mod]['total_create_payload']}({class_stats[mod]['payload_create_coverage']}%)")
        msg_stats_line.append(f"{class_stats[mod]['used_replace_payload']}/{class_stats[mod]['total_replace_payload']}({class_stats[mod]['payload_replace_coverage']}%)")
        msg_stats_line.append(f"{class_stats[mod]['used_update_payload']}/{class_stats[mod]['total_update_payload']}({class_stats[mod]['payload_update_coverage']}%)")
        msg_stats_rows.append(msg_stats_line)
        filepath = os.path.join(get_logs_path(), "message_coverage", f"{mod}.html")
        utils.write_html_table2(msg_stats_header, msg_stats_rows, filepath)

        if not consolidated:
            # pickle raw stats for consolidated report
            filepath_pkl = os.path.join(get_logs_path(), "message_coverage", "stats.pkl")
            with open(filepath_pkl, "wb") as fp:
                # nosemgrep-next-line
                pickle.dump(run_data, fp)

    mod_stats_rows = []
    colors = []
    mod_stats_header = ["Modules", "Total Coverage", "# of Messages Tested", "GET-Coverage", "CREATE-Coverage", "REPLACE-Coverage", "UPDATE-Coverage", "DELETE-Coverage", "SUBSCRIBE-Coverage", "Payload-Create-Coverage", "Payload-Replace-Coverage", "Payload-Update-Coverage"]
    for mod in sorted(stats["all_mods"]):
        used_coverage = class_stats[mod]['used_get'] + class_stats[mod]['used_create'] + class_stats[mod]['used_replace'] + class_stats[mod]['used_update'] + class_stats[mod]['used_delete'] + class_stats[mod]['used_subscribe'] + class_stats[mod]['used_create_payload'] + class_stats[mod]['used_replace_payload'] + class_stats[mod]['used_update_payload']
        total_coverage = class_stats[mod]['total_get'] + class_stats[mod]['total_create'] + class_stats[mod]['total_replace'] + class_stats[mod]['total_update'] + class_stats[mod]['total_delete'] + class_stats[mod]['total_subscribe'] + class_stats[mod]['total_create_payload'] + class_stats[mod]['total_replace_payload'] + class_stats[mod]['total_update_payload']
        mod_stats_line = []
        mod_stats_line.extend([f"<a href='{mod}.html'>{mod}</a>"])
        mod_stats_line.extend([f"{used_coverage}/{total_coverage}({class_stats[mod]['total_coverage']}%)"])
        mod_stats_line.extend([f"{len(class_stats[mod]['used_classes'])}/{len(class_stats[mod]['all_classes'])}({round(len(class_stats[mod]['used_classes'])/len(class_stats[mod]['all_classes'])*100)}%)"])
        mod_stats_line.extend([f"{class_stats[mod]['used_get']}/{class_stats[mod]['total_get']}({class_stats[mod]['get_coverage']}%)"])
        mod_stats_line.extend([f"{class_stats[mod]['used_create']}/{class_stats[mod]['total_create']}({class_stats[mod]['create_coverage']}%)"])
        mod_stats_line.extend([f"{class_stats[mod]['used_replace']}/{class_stats[mod]['total_replace']}({class_stats[mod]['replace_coverage']}%)"])
        mod_stats_line.extend([f"{class_stats[mod]['used_update']}/{class_stats[mod]['total_update']}({class_stats[mod]['update_coverage']}%)"])
        mod_stats_line.extend([f"{class_stats[mod]['used_delete']}/{class_stats[mod]['total_delete']}({class_stats[mod]['delete_coverage']}%)"])
        mod_stats_line.extend([f"{class_stats[mod]['used_subscribe']}/{class_stats[mod]['total_subscribe']}({class_stats[mod]['subscribe_coverage']}%)"])
        mod_stats_line.extend([f"{class_stats[mod]['used_create_payload']}/{class_stats[mod]['total_create_payload']}({class_stats[mod]['payload_create_coverage']}%)"])
        mod_stats_line.extend([f"{class_stats[mod]['used_replace_payload']}/{class_stats[mod]['total_replace_payload']}({class_stats[mod]['payload_replace_coverage']}%)"])
        mod_stats_line.extend([f"{class_stats[mod]['used_update_payload']}/{class_stats[mod]['total_update_payload']}({class_stats[mod]['payload_update_coverage']}%)"])
        mod_stats_rows.append(mod_stats_line)
        colors.append('yellow')

        stats["total_msg"] += len(class_stats[mod]['all_classes'])
        stats["used_msg"] += len(class_stats[mod]['used_classes'])
        if stats["total_msg"] > 0:
            stats["msg_coverage"] = round(stats["used_msg"] / stats["total_msg"] * 100)

        stats["total_get"] += class_stats[mod]['total_get']
        stats["used_get"] += class_stats[mod]['used_get']
        if stats["total_get"] > 0:
            stats["get_coverage"] = round(stats["used_get"] / stats["total_get"] * 100)

        stats["total_create"] += class_stats[mod]['total_create']
        stats["used_create"] += class_stats[mod]['used_create']
        if stats["total_create"] > 0:
            stats["create_coverage"] = round(stats["used_create"] / stats["total_create"] * 100)

        stats["total_replace"] += class_stats[mod]['total_replace']
        stats["used_replace"] += class_stats[mod]['used_replace']
        if stats["total_replace"] > 0:
            stats["replace_coverage"] = round(stats["used_replace"] / stats["total_replace"] * 100)

        stats["total_update"] += class_stats[mod]['total_update']
        stats["used_update"] += class_stats[mod]['used_update']
        if stats["total_update"] > 0:
            stats["update_coverage"] = round(stats["used_update"] / stats["total_update"] * 100)

        stats["total_delete"] += class_stats[mod]['total_delete']
        stats["used_delete"] += class_stats[mod]['used_delete']
        if stats["total_delete"] > 0:
            stats["delete_coverage"] = round(stats["used_delete"] / stats["total_delete"] * 100)

        stats["total_subscribe"] += class_stats[mod]['total_subscribe']
        stats["used_subscribe"] += class_stats[mod]['used_subscribe']
        if stats["total_subscribe"] > 0:
            stats["subscribe_coverage"] = round(stats["used_subscribe"] / stats["total_subscribe"] * 100)

        stats["total_create_payload"] += class_stats[mod]['total_create_payload']
        stats["used_create_payload"] += class_stats[mod]['used_create_payload']
        if stats["total_create_payload"] > 0:
            stats["payload_create_coverage"] = round(stats["used_create_payload"] / stats["total_create_payload"] * 100)

        stats["total_replace_payload"] += class_stats[mod]['total_replace_payload']
        stats["used_replace_payload"] += class_stats[mod]['used_replace_payload']
        if stats["total_replace_payload"] > 0:
            stats["payload_replace_coverage"] = round(stats["used_replace_payload"] / stats["total_replace_payload"] * 100)

        stats["total_update_payload"] += class_stats[mod]['total_update_payload']
        stats["used_update_payload"] += class_stats[mod]['used_update_payload']
        if stats["total_update_payload"] > 0:
            stats["payload_update_coverage"] = round(stats["used_update_payload"] / stats["total_update_payload"] * 100)

    used_coverage = stats['used_get'] + stats['used_create'] + stats['used_replace'] + stats['used_update'] + stats['used_delete'] + stats['used_subscribe'] + stats['used_create_payload'] + stats['used_replace_payload'] + stats['used_update_payload']
    total_coverage = stats['total_get'] + stats['total_create'] + stats['total_replace'] + stats['total_update'] + stats['total_delete'] + stats['total_subscribe'] + stats['total_create_payload'] + stats['total_replace_payload'] + stats['total_update_payload']
    stats["total_coverage"] = round((used_coverage / total_coverage) * 100)
    stats_line = [f"{len(stats['used_mods'])}/{len(stats['all_mods'])}({round(len(stats['used_mods'])/len(stats['all_mods'])*100)}%)"]
    colors.append('yellow')
    stats_line.extend([f"{used_coverage}/{total_coverage}({stats['total_coverage']}%)"])
    stats_line.extend([f"{stats['used_msg']}/{stats['total_msg']}({stats['msg_coverage']}%)"])
    stats_line.extend([f"{stats['used_get']}/{stats['total_get']}({stats['get_coverage']}%)"])
    stats_line.extend([f"{stats['used_create']}/{stats['total_create']}({stats['create_coverage']}%)"])
    stats_line.extend([f"{stats['used_replace']}/{stats['total_replace']}({stats['replace_coverage']}%)"])
    stats_line.extend([f"{stats['used_update']}/{stats['total_update']}({stats['update_coverage']}%)"])
    stats_line.extend([f"{stats['used_delete']}/{stats['total_delete']}({stats['delete_coverage']}%)"])
    stats_line.extend([f"{stats['used_subscribe']}/{stats['total_subscribe']}({stats['subscribe_coverage']}%)"])
    stats_line.extend([f"{stats['used_create_payload']}/{stats['total_create_payload']}({stats['payload_create_coverage']}%)"])
    stats_line.extend([f"{stats['used_replace_payload']}/{stats['total_replace_payload']}({stats['payload_replace_coverage']}%)"])
    stats_line.extend([f"{stats['used_update_payload']}/{stats['total_update_payload']}({stats['payload_update_coverage']}%)"])
    mod_stats_rows.append(stats_line)
    filepath = os.path.join(get_logs_path(), "message_coverage", "index.html")
    utils.write_html_table2(mod_stats_header, mod_stats_rows, filepath, colors=colors, color_col="Total Coverage")
