#!/bin/bash
#pull links out of pdf files
#hadojae
#param is path to pdf files
#REQUIRES pdf-parser.py from https://blog.didierstevens.com/programs/pdf-tools/

cd $1

for i in *
do

file_type="$(file -b $i)"

if [ "${file_type%%,*}" == "PDF document" ]; then
    egrep -i -a -r -o --no-filename "http[^)]+" $i >> pdf_links.tmp
    python ~/pdf/pdf-parser.py --searchstream --regex "https?:\/" --filter $i | egrep -i -a -o "http[^)\"\']+" >> pdf_links.tmp
fi

done

#format up the file for printing

sort -u pdf_links.tmp | egrep -i -v -a "(DidierStevens\.com|fonts\.com|typoland\.com|monotypeimaging\.com|monotype\.com|dynaforms\.com|youtube\.com|radpdf\.com|igouv\.fr|support\.microsoft\.com|maps\.google\.com|wikipedia\.org|mitre\.org|code\.google\.com|www\.w3\.org|purl\.org|adobe\.com|convertapi\.com|wondershare\.net|iec\.ch|verisign\.com|microsoft\.com|neevia\.com|aiim\.org|pdf\-tools\.com|color\.org)";

#cleanup
rm pdf_links.tmp
