# Troubleshooting

## The report says the file is not valid

Each line is read on its own: RFC 5424 (<PRI>1 timestamp host app ...), BSD syslog with or without <PRI> (Mmm dd hh:mm:ss host program[pid]: message, or an ISO timestamp), and CEF events with or without a syslog header. Lines that match none of these are listed in the parse check with the reason.

## The file is too large

Reports read files up to the size set in `syslogAtlas.maxFileSizeMB` (50 MB by default and at most). VS Code passes files only up to 50 MB to extensions, so a larger file cannot be read by any extension: split it, or save a shorter one.

## The preview does not open

The report always opens as a Markdown document. If the preview stays closed, set `syslogAtlas.openReportsAsPreview` to true and check that the built-in Markdown extension is enabled.

## Pro or the trial does not unlock

Run **Syslog Atlas: Show Licence Status**. It tells whether a key is stored, whether it was checked, and how many trial days are left. Details are in [licence.md](licence.md).

## Something else

Run **Syslog Atlas: Report A Problem**. It copies a diagnostics block (versions, settings, licence state; no file contents) and opens the issues page.
