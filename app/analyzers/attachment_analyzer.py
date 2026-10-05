DANGEROUS_EXTENSIONS = {
    ".exe": "Windows executable",
    ".scr": "Screen saver executable",
    ".com": "DOS executable",
    ".bat": "Batch script",
    ".cmd": "Command script",
    ".ps1": "PowerShell script",
    ".vbs": "VBScript",
    ".vbe": "Encoded VBScript",
    ".js": "JavaScript file",
    ".jse": "Encoded JavaScript",
    ".wsf": "Windows Script File",
    ".wsh": "Windows Script Host file",
    ".hta": "HTML Application",
    ".dll": "Dynamic-link library",
    ".jar": "Java archive",
    ".lnk": "Windows shortcut",
    ".iso": "Disk image",
    ".img": "Disk image",
    ".msi": "Windows installer",
    ".msp": "Windows installer patch"
}


SUSPICIOUS_EXTENSIONS = {
    ".zip": "Archive file",
    ".rar": "RAR archive",
    ".7z": "7-Zip archive",
    ".tar": "TAR archive",
    ".gz": "GZIP archive",
    ".docm": "Word document with macros",
    ".xlsm": "Excel document with macros",
    ".pptm": "PowerPoint document with macros",
    ".xlam": "Excel macro-enabled add-in",
    ".html": "HTML file",
    ".htm": "HTML file"
}


def analyze_attachments(attachments):
    """
    Analyze attachment metadata without opening or executing files.
    """

    results = []

    for attachment in attachments:

        filename = attachment.get("filename", "")
        content_type = attachment.get("content_type", "")
        size = attachment.get("size", 0)

        filename_lower = filename.lower()

        extension = ""

        if "." in filename_lower:
            extension = "." + filename_lower.rsplit(".", 1)[1]

        if extension in DANGEROUS_EXTENSIONS:

            results.append({
                "filename": filename,
                "content_type": content_type,
                "size": size,
                "extension": extension,
                "risk": "HIGH",
                "reason": DANGEROUS_EXTENSIONS[extension]
            })

        elif extension in SUSPICIOUS_EXTENSIONS:

            results.append({
                "filename": filename,
                "content_type": content_type,
                "size": size,
                "extension": extension,
                "risk": "MEDIUM",
                "reason": SUSPICIOUS_EXTENSIONS[extension]
            })

        else:

            results.append({
                "filename": filename,
                "content_type": content_type,
                "size": size,
                "extension": extension,
                "risk": "LOW",
                "reason": "No suspicious attachment extension detected"
            })

    return results