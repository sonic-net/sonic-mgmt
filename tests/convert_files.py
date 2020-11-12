import os, fnmatch
import re

pattern = re.compile('^.*def test_.*\(.*duthost[\,\)]')
comments_1 = re.compile('^.*\"\"\"')
comments_2 = re.compile('^.*\'\'\'')

def findReplace():
    directory = os.getcwd()
    filePattern = "test_*py"
    print("begin")
    for path, dirs, files in os.walk(os.path.abspath(directory)):
        for filename in fnmatch.filter(files, filePattern):
            filepath = os.path.join(path, filename)
            with open(filepath) as f:
                s = f.read()
                res = []
                matched = False
                matching_end = False
                def_cont = False

                for line in s.splitlines():
                    if def_cont:
                        if line.endswith("):"):
                            def_cont = False
                        res.append(line)
                        continue

                    if matching_end and (comments_1.match(line) or comments_2.match(line)):
                        res.append(line)
                        res.append("{}duthost = duthosts[rand_one_dut_hostname]".format(" "*indent))
                        matching_end = False
                        continue
                   
                    if matched:                            
                        if (comments_1.match(line) or comments_2.match(line)):
                            if line.count("\"\"\"") == 2 or line.count("\'\'\'") == 2:
                                res.append(line)
                                res.append("{}duthost = duthosts[rand_one_dut_hostname]".format(" "*indent))
                                matched = False
                                continue
                            matching_end = True
                            matched = False
                        else:
                            res.append("{}duthost = duthosts[rand_one_dut_hostname]".format(" "*indent))
                            res.append(line)
                            matched = False
                            continue

                    if pattern.match(line):
                        indent = line.index('test_')
                        line = line.replace('duthost','duthosts, rand_one_dut_hostname')
                        res.append(line)
                        #res.append("{}duthost = duthosts[rand_one_dut_hostname]".format(" "*indent))
                        if not line.endswith("):"):
                            def_cont = True
                        matched = True
                        continue

                    res.append(line)
            with open(filepath, "w") as f:
                for line in res:
                    f.write(line)
                    f.write('\n')

findReplace()
