#!python

class TextTable():

    def __init__(self, field_names=None):
        self.widths = []
        self.table = []
        self._field_names = None
        if field_names:
            self._field_names = field_names
            for name in field_names:
                self.widths.append(len(name))

    def get_field_names(self):
        return self._field_names

    def set_field_names(self, field_names):
        if self._field_names:
            return
        if not field_names:
            return
        self._field_names = field_names
        for name in field_names:
            self.widths.append(len(name))

    field_names = property(get_field_names, set_field_names)

    def add_row(self, row):
        if not row:
            return False
        if not self._field_names:
            return False
        if len(row) != len(self.widths):
            return False
        self.table.append(row)
        for index, item in enumerate(row):
            if self.widths[index] < len(str(item)):
                self.widths[index] = len(str(item))

    def __str__(self):
        if not self._field_names:
            return ''

        line = '+' + '+'.join(['-' * (width + 2)
                              for width in self.widths]) + '+'

        # field names
        buf = line
        buf += '\n| ' + ' | '.join([str(name).center(self.widths[index])
                                   for index, name in enumerate(self._field_names)]) + ' |'
        buf += '\n' + line

        # table
        for row in self.table:
            buf += '\n| ' + ' | '.join([str(item).center(self.widths[index])
                                       for index, item in enumerate(row)]) + ' |'

        # last line
        if self.table:
            buf += '\n' + line

        return buf


if __name__ == '__main__':
    table1 = TextTable(['f1', 'f22', 'f333', 'f4444', 'f55555',
                       'f666666', 'f7777777', 'f88888888', 'f999999999'])
    print('table1 only fields')
    print(table1)

    table1.add_row(['v999999999', 'v88888888', 'v7777777',
                   'v666666', 'v55555', 'v4444', 'v333', 'v22', 'v1'])
    print('table1 add row')
    print(table1)

    table2 = TextTable()
    print('table2 empty')
    print(table2)

    table2.field_names = ['1f', '2ff', '3fff', '4ffff', '5fffff']
    print('table2 set fields')
    print(table2)

    table2.add_row(['1', '2', '3', '4', '5'])
    print('table2 add row')
    print(table2)

    table3 = TextTable(['field'] + ['f1', 'f22', 'f333', 'f4444',
                       'f55555', 'f666666', 'f7777777', 'f88888888', 'f999999999'])
    print('table3 only fields')
    print(table3)

    table3.add_row([''] + ['v999999999', 'v88888888', 'v7777777',
                   'v666666', 'v55555', 'v4444', 'v333', 'v22', 'v1'])
    print('table3 add row')
    print(table3)

    table3.add_row(['row2'] + ['v999999999', 'v88888888', 'v7777777',
                   'v666666', 'v55555', 'v4444', 'v333', 'v22', 'v1'])
    print('table3 more rows')
    print(table3)
