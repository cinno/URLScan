URLScan
=======

Takes an input URL and scans for spam (on SURBL and SpamHaus), then follows redirects and scans that final url in virustotal's api.

Made to practice use of bloom filters, with a basic implementation used for a local virus scanner on files that are suspicious, so that the virustotal API is not used too much. It scales with the size of the database, so as long as the total number of elements * 3 is less than the amount of available ram it will work.
