#!/bin/bash

cat | awk '
# Match only lines starting with ; and containing @ file:line
/^;/ && /@ [^:]+:[0-9]+/ {
    if (current != "") {
        print current, count
    }
    match($0, /@ ([^:]+):([0-9]+)/, arr)
    filename = arr[1]
    if (filename == "udpgrm_internal.h") {
        filename = "include/" filename
    } else {
        filename = "ebpf/" filename
    }
    file_count[filename]++
    lineno = arr[2]
    current = filename ":" lineno
    count = 0
    next
}

# Match only lines that start with a number followed by a colon (e.g., 123: ...)
/^[0-9]+: [(]/ {
    if (current != "") {
        file_count[filename]++
        count++
    }
}

END {
    if (current != "") {
        print current, count
    }
    #for (f in file_count) {
    #    print f, file_count[f]
    #}

}
' | \
awk -F '[: ]+' '
{
    file = $1
    line = $2
    count = $3
    key = file ":" line
    file_line_counts[key] += count
    files[file] = 1
}
END {
    for (f in files) {
        print "TN:"
        print "SF:" f
        for (k in file_line_counts) {
            split(k, parts, ":")
            if (parts[1] == f) {
                print "DA:" parts[2] "," file_line_counts[k]
            }
        }
        print "end_of_record"
    }
}
'
