from sys import platform as _platform
#
#  This is some hokey code but it works.  Code should clean up and eliminate
#  header properly but if not you'll need to delete them and rerun.
#
wtype = input("Enter 1 for audit log 2 for event log: ")
if _platform == "win32":
    filename = input("Please enter filename to process:(c:\\fname.txt) ")
elif _platform == "linux" or _platform == "linux2" or _platform == "darwin":
    filename = input("Please enter filename to process:(/fname.txt) ")
else:
    sys.exit('OS type not supported')

# Read the contents of the file into memory.
with open(filename, 'r') as infile:
    data = infile.read()

# open output file    
ofile = open(filename + "_out",'w')

#process data
my_list = data.splitlines()
if wtype == "1":
    # write header
    ofile.write("Record Number%Time%Host Name%OS Name%Client Host%Function Class%Action Code%"+ \
            "Text%Username\n")
    for line in my_list:
        s = line.split(":")
        if ("              A U D I T   L O G   D A T A" in s) or (line == ""):
            continue
        else:
            header = s[0].strip()
            data = s[1].strip()
            if header == "Record Number" or header == "Host Name" \
            or header == "OS Name" or header == "Client Host" \
            or header == "Function Class" \
            or header == "Action Code":
                ofile.write(data + "%")
            if header == "Time":
                data = data + ":" + s[2]+ ":" + s[3]
                ofile.write(data + "%")
            if header == "Text":
                d2 = line[26:]
                ofile.write(d2 + "%")
            if header == "Username":
                d2 = line[26:]
                ofile.write(d2 + "\n")
elif wtype == "2":
    # write header
    ofile.write("Time%Director%Source%Category%Severity%Numeric Code%"+ \
            "Event Code Symbol%Description\n")
    for line in my_list:
        s = line.split(":")
        if ("Symmetrix ID" in s) or (line == ""):
            continue
        else:
            header = s[0].strip()
            data = s[1].strip()
            if "Event at" in line:
                ofile.write(line + "%")
            if header == "Reporting Director" or header == "Source" \
            or header == "Category" or header == "Severity" \
            or header == "Numeric Code" \
            or header == "Event Code Symbol":
                ofile.write(data + "%")
            if header == "Description":
                ofile.write(data + "\n")
else:
    print('Bad input value')

ofile.close()


