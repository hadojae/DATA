#!/bin/bash
#pull links out of pdf files
#hadojae
#param is path to pdf files

pdf_parser_loc=''

if [ -z $pdf_parser_loc ]; then
    echo -e "\nPlease set the full path location of pdf-parser.py in the first line of the script."
    echo -e "eg. '/home/user/downloads/pdf-parser.py' " 
    echo -e "Pdf parser can be downloaded from https://blog.didierstevens.com/programs/pdf-tools/\n"
    exit
fi

cd $1

for i in *
do

file_type="$(file -b $i)"

if [ "${file_type%%,*}" == "PDF document" ]; then
    egrep -i -a -r -o --no-filename "http[^)]+" $i >> pdf_links.tmp
    egrep -i -a -o --no-filename "\/URI\s*\([^)]+\)" $i | sed -r 's/.*\(([^)]+)\).*/\1/' >> pdf_links.tmp
    python $pdf_parser_loc --regex --searchstream="https?:\/" --filter $i | egrep -i -a -o "http[^)\"\']+" >> pdf_links.tmp
fi

done

#if we found some urls, remove fp's, print file, and cleanup
if [ -f pdf_links.tmp ]; then
    sort -u pdf_links.tmp | egrep -i -v -a "(DidierStevens\.com|fonts\.com|typoland\.com|monotypeimaging\.com|monotype\.com|dynaforms\.com|youtube\.com|radpdf\.com|igouv\.fr|support\.microsoft\.com|maps\.google\.com|wikipedia\.org|mitre\.org|code\.google\.com|www\.w3\.org|purl\.org|adobe\.com|convertapi\.com|wondershare\.net|iec\.ch|verisign\.com|microsoft\.com|neevia\.com|aiim\.org|pdf\-tools\.com|color\.org)";
    rm pdf_links.tmp
fi
