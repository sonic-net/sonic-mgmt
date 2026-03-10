import sys
from enum import Enum
from pyparsing import ZeroOrMore, Optional
from pyparsing import Word, alphanums
from spytest import st


class QueryParamType(Enum):
    """Specifies the type of the query parameters
    """
    FIELDS = 1
    CONTENT = 2
    DEPTH = 3


class YangDataType(Enum):
    """Specifies the type of the 'content' query parameter values
    """
    ALL = 1
    CONFIG = 2
    NON_CONFIG = 3


class FieldQueryParser(object):
    """FieldQueryParser class to parse the field query and create the tree dictionary of the nodes
    """

    def __init__(self, fields):
        """
            Parameters:
               fields  field query path tokens
        """
        self.fields = fields
        self.path_dict = {}
        self.parse()

    @staticmethod
    def add_path(tkn, path_dict):
        """add_path add the field path node in the tree dictionary of the nodes

            Parameters:
               tkn       string; node of the path
               path_dict tree dictionary of the nodes
        """
        tmp_dict = {}
        str_list = tkn.split(":", 1)
        if len(str_list) > 1:
            tkn = str_list[1]
        if tkn in path_dict:
            return path_dict[tkn]
        else:
            path_dict[tkn] = tmp_dict
        path_dict = tmp_dict
        st.log("FieldQueryParser: add_path: path_dict:  {}".format(path_dict))
        return path_dict

    def parse(self):
        """parse parse the given fields to create the dictionary of nodes
        """
        path_dict = self.path_dict
        same_path = False
        parent_dict = self.path_dict
        for tkn in self.fields:
            if tkn == "/":
                continue
            if tkn == "(":
                same_path = True
                parent_dict = path_dict
                continue
            elif tkn == ")":
                same_path = False
                parent_dict = self.path_dict
                continue
            if same_path and tkn == ";":
                path_dict = parent_dict
            elif tkn == ";":
                path_dict = self.path_dict
            else:
                path_dict = self.add_path(tkn, path_dict)
        st.log("FieldQueryParser: parse: path_dict:  {}".format(self.path_dict))


class FieldsParam(object):
    """To represent the 'fields' Query Parameter for the REST API
    """

    def __init__(self, *fields):
        """
            Parameters:
               fields  variable number of arguments of the type string to pass one or more field query parameter values
        """
        self.fields = fields
        self.type = QueryParamType.FIELDS
        self.fields_str = self.append_fields()

    def append_fields(self):
        fields_str = ""
        for field in self.fields:
            if len(fields_str) > 0:
                fields_str = fields_str + ";" + field
            else:
                fields_str = field
        return fields_str

    def append(self, query_param):
        """To append the query field query param to the existing FieldsParam object

            Parameters:
               query_param  string; field query param
        """
        if len(self.fields_str) > 0:
            self.fields_str += ";" + query_param
        else:
            self.fields_str = query_param

    def query_str(self):
        """Returns field query string format of the field param
        """
        if len(self.fields_str) > 0:
            return "fields=" + self.fields_str
        return ""

    def get_value(self):
        """To get the value of the field query param
        """
        if len(self.fields_str) > 0:
            st.log("FieldQueryParser: input query fields: {}".format(self.fields_str))
            fields_expr = ZeroOrMore(Optional("/") + Optional(";") + Optional("(")
                                     + Word(alphanums + "`~!@$%^&*?_-+=|:\"'><.,\\}{[]") + Optional(")") + Optional(
                ";") + Optional("/"))
            path_tokens = fields_expr.parseString(self.fields_str).asList()
            st.log("FieldQueryParser: path_tokens: {}".format(path_tokens))
            return FieldQueryParser(path_tokens).path_dict
        else:
            return None


class ContentParam(object):
    """To represent the 'content' Query Parameter for the REST API
    """

    def __init__(self, content=None, gnmi_opertional_filter=False):
        """
            Parameters:
               content                to specify the content of the type YangDataType
               gnmi_opertional_filter boolean; to specify gnmi operational filter in the query param
        """
        self.rest_content = "all"
        self.gnmi_filter = None
        self.content = "all"
        self.type = QueryParamType.CONTENT
        if gnmi_opertional_filter is True:
            self.gnmi_filter = "OPERATIONAL"
            self.content = "operational"
        elif content is None or content == YangDataType.ALL:
            self.rest_content = "all"
            self.content = "all"
        elif content == YangDataType.CONFIG:
            self.rest_content = "config"
            self.gnmi_filter = "CONFIG"
            self.content = "config"
        elif content == YangDataType.NON_CONFIG:
            self.rest_content = "nonconfig"
            self.gnmi_filter = "STATE"
            self.content = "state"
        else:
            raise ValueError("Invalid 'content' query parameter value: " + content)

    def get_value(self):
        """Returns the value of the content query param
        """
        # st.log("ContentParam: content: {}".format(self.content))
        return self.content

    def get_gnmi_filter(self):
        """Returns the value of the gnmi filter content query param
        """
        return self.gnmi_filter

    def query_str(self):
        """Returns query string format of the content query param
        """
        return "content=" + self.rest_content


class DepthParam(object):
    """To represent the 'depth' Query Parameter for the REST API
    """

    def __init__(self, depth=0):
        self.depth = depth
        self.type = QueryParamType.DEPTH

    def get_value(self):
        """Returns the value of the depth query param
        """
        return self.depth

    def query_str(self):
        """Returns query string format of the depth query param
        """
        if self.depth < 0:
            raise ValueError("Invalid 'depth' query parameter value: " + str(self.depth))
        return "depth=" + str(self.depth)


class QueryParam(object):
    """To represent the Query Parameter for the REST and GNMI filtering
    """

    def __init__(self):
        self.content_obj = None
        self.depth_obj = None
        self.field_obj = None

    def reset(self):
        """reset sets all the query param to None
        """
        self.content_obj = None
        self.depth_obj = None
        self.field_obj = None

    def set_fields(self, *fields):
        """set_fields set the given variable list 'fields' query parameter

        Parameters:
           fields    strings; variable argument to pass one or more field query parameter values
        """
        self.field_obj = FieldsParam(*fields)

    def unset_fields(self):
        """unset_fields removes the field param from the query param object
        """
        self.field_obj = None

    def append_fields(self, field_query):
        """append_fields append the 'field_query' query parameter

        Parameters:
           field_query  string; field query parameter
        """
        if self.field_obj is None:
            self.field_obj = FieldsParam(field_query)
        else:
            self.field_obj.append(field_query)

    def set_content(self, content=YangDataType.ALL):
        """set_content set the value for the 'content' query parameter.

        Parameters:
           content       Enum of type YangDataType to indicate the
                         type of content query parameter value
        """
        self.content_obj = ContentParam(content)

    def unset_content(self):
        """unset_content removes the content param from the query param object
        """
        self.content_obj = None

    def set_gnmi_operational_type(self):
        """ set the GNMI query filter value as 'operational' for the GNMI Interface;
            This method does not have any impact on REST API query filter.

        Parameters:
           gnmi_opertional_filter   Boolean; value 'True' indicate the filter type as OPERATIONAL
        """
        self.content_obj = ContentParam(gnmi_opertional_filter=True)

    def set_depth(self, depth=0):
        """set_depth set the value for the 'depth' query parameter

        Parameters:
           depth   Integer value to indicate the value of the depth query parameter
        """
        self.depth_obj = DepthParam(depth)

    def unset_depth(self):
        """unset_content removes the depth param from the query param object
        """
        self.depth_obj = None

    def query_str(self):
        """query_str returns query parameter fields in a query string format
        """
        query_str_prefix = "?"
        query_str = ""
        if self.depth_obj is not None:
            query_str = query_str + self.depth_obj.query_str()
        if self.content_obj is not None:
            if len(query_str) != 0:
                query_str = query_str + "&"
            query_str = query_str + self.content_obj.query_str()
        if self.field_obj is not None:
            fld_query = self.field_obj.query_str()
            if len(fld_query) > 0:
                if len(query_str) > 0:
                    query_str = query_str + "&" + fld_query
                else:
                    query_str = fld_query
        if len(query_str) > 0:
            query_str = query_str_prefix + query_str
        # st.log("QueryParam: query string: {}".format(query_str))
        return query_str

    def get_gnmi_filter(self):
        """Returns gnmi filter
        """
        if self.content_obj is not None:
            return self.content_obj.get_gnmi_filter()
        else:
            return None

    def get_depth(self):
        """Returns value of the depth query param
        """
        if self.depth_obj is not None and self.depth_obj.get_value() > 0:
            return self.depth_obj.get_value()
        else:
            return sys.maxsize

    def get_content(self):
        """Returns value of the content query param
        """
        if self.content_obj is not None:
            return self.content_obj.get_value()
        else:
            return "all"

    def get_fields(self):
        """Returns value of the fields query param
        """
        if self.field_obj is not None:
            return self.field_obj.get_value()
        else:
            return None
