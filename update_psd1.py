import re
import datetime

# Path to WSTools.psd1
psd1_file = "WSTools/WSTools.psd1"

# Function to increment semantic version
def increment_version(version):
    major, minor, patch = map(int, version.split("."))
    patch += 1
    return f"{major}.{minor}.{patch}"

# Read the .psd1 file
with open(psd1_file, "r") as file:
    content = file.readlines()

# Update version and date
updated_content = []
for line in content:
    # Update the ModuleVersion
    if "ModuleVersion" in line:
        current_version = re.search(r"'([\d\.]+)'", line).group(1)
        new_version = increment_version(current_version)
        line = re.sub(r"'([\d\.]+)'", f"'{new_version}'", line)

    # Update the GUID
    if "GUID" in line:
        new_guid = str(datetime.datetime.now().strftime('%Y%m%d%H%M%S%f'))
        line = re.sub(r"'[0-9A-Fa-f-]+'", f"'{new_guid}'", line)

    # Update Release Notes
    if "ReleaseNotes" in line:
        new_date = datetime.datetime.now().strftime("%Y-%m-%d")
        line = f"    ReleaseNotes = @(\"Updated for release on {new_date}\")\n"

    updated_content.append(line)

# Write changes back to the .psd1 file
with open(psd1_file, "w") as file:
    file.writelines(updated_content)
