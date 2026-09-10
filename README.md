# dfc_security_reporter

## Purpose and Scope

`dfc_security_reporter.py` is a generic security-reporting tool for an **Out of the Path** solution. It transforms forensic attack exports and DefenseFlow detector logs into consistent security analysis reports for different customers and environments.

The tool is customer-independent. Customer names are not required to run the report because the report describes the observed attack activity, protected destinations, detector source, timing, traffic volume, and risk indicators rather than customer configuration.

The same workflow supports these detector types and can be adapted to different customer deployments through configuration:

- **Kentik**: Kentik external-detector events and DefenseFlow activation history.
- **Arbor**: Arbor Peakflow external-detector events and DefenseFlow activation history.
- **DefensePro**: DefensePro (`DEFENSE_PRO`) detector events captured in DefenseFlow support logs.

For a detector with an operation-based workflow, the activation chart can count matching `triggered up operation <operation-name>` lines from the alert/detection logs. Attack cycles remain a separate metric based on unique external attack IDs, so the two totals may differ.

The optional activation substring can be configured in each detector section in `dfc_security_reporter.ini`. When it is blank, DefensePro automatically selects the most frequent `triggered up operation` found in the selected logs; other detectors use the default attack-cycle activation logic.

The tool supports weekly and monthly reporting periods, configurable date filters, multiple DefenseFlow support archives, and both CSV and interactive HTML output.

## How the Tool Works

This section describes the **automatic workflow inside the script**. It is not a second set of commands that you need to run manually. For the user-facing steps, see [Usage](#usage) and [Workflow](#workflow).

### What You Provide

Before running the tool, place the source files in the appropriate folders:

1. Put the forensic CSV or ZIP export in `Inputs/Forensics Input/`.
2. Put available DefenseFlow support archives or extracted folders in `Inputs/DefenseFlow Input/`.
3. Set the desired date range in `dfc_security_reporter.ini`, or provide it with `--start-time` and `--end-time`.

### What the Script Does Automatically

After you start the tool, it performs these steps:

1. **Identifies the report context**: Uses the selected detector type, Kentik, Arbor, or DefensePro, and the selected report period, weekly or monthly.
2. **Loads the forensic data**: Reads the selected CSV, or the first CSV inside a ZIP file, from `Inputs/Forensics Input/`.
3. **Standardizes the data**: Maps common column-name variations such as `Start`, `End`, `Dst IP`, `Peak pps`, and `Peak bps` to a consistent internal format.
4. **Applies the date scope**: Parses common detector timestamp formats, including slash and dot separators, and keeps only records inside the configured date range.
5. **Removes unusable destinations**: Excludes invalid destination values such as `0.0.0.0` and `Multiple` from campaign analysis.
6. **Builds attack campaigns**: Groups events by destination IP and combines nearby events according to the configured gap. Destination-port separation can be enabled when required.
7. **Searches DefenseFlow history**: Inspects all available `dfc_support*` archives and folders, including nested bundles such as `standby_support.zip`, so older detector history can be included.
8. **Builds detector attack cycles**: Reads matching detector attack-start and attack-end records, removes duplicate records from overlapping archives, and creates one cycle per external detector ID.
9. **Creates the deliverables**: Writes the campaign, activation, raw-event, and attack-cycle CSV files and creates the interactive HTML report.

Activation totals come from the same deduplicated attack cycles used in the report. This keeps the activation chart, activation CSV, and attack-cycle CSV aligned even when several DefenseFlow archives contain overlapping history.

## Directory Structure

```
C:\your\path\dfc_security_reporter\
├── dfc_security_reporter.py         # Main script
├── dfc_security_reporter.ini        # Configuration file
├── Inputs/
│   ├── Forensics Input/              # Place forensic CSV/ZIP files here
│   └── DefenseFlow Input/            # Place DefenseFlow logs/ZIP files here
└── Reports/                          # All final HTML and CSV reports go here
```

### Input Responsibilities

- `Inputs/Forensics Input/`: forensic attack CSV or ZIP exports. This is the primary source for campaign analysis, traffic measurements, risk values, policies, and destination details.
- `Inputs/DefenseFlow Input/`: DefenseFlow support ZIP files or extracted support folders. These provide detector activation, start/end events, external IDs, and historical coverage that may extend beyond the newest support archive.
- `Reports/`: generated CSV and HTML reports. Existing files are not overwritten because each output includes a timestamp.

## Configuration File: dfc_security_reporter.ini

The configuration file manages:
- **Paths**: Shared Forensics and DefenseFlow input directories
- **Processing**: Default parameters (gap time, encoding, etc.)
- **Units**: Display units for bandwidth and packet rates
- **Detector Settings**: Kentik, Arbor, and DefensePro detector-specific behavior
- **Processing**: Generic settings that apply to any customer

## Usage

### Interactive Mode (Recommended)

Simply run the script and follow the prompts:

```powershell
python dfc_security_reporter.py
```

The script will ask you to select:
1. **Detector Type**: Kentik, Arbor, or DefensePro
2. **Report Period**: Weekly or Monthly

Customer identity is intentionally not part of the workflow.

It will then auto-select the latest CSV or ZIP file from `Inputs/Forensics Input/`.

### Command-Line Mode

#### Full Processing (CSV to HTML Report)

```powershell
# Process specific file
python dfc_security_reporter.py "Inputs/Forensics Input/attacks.csv" --detector-type kentik

# Non-interactive mode with specific file
python dfc_security_reporter.py --detector-type kentik --non-interactive

# With custom parameters
python dfc_security_reporter.py --detector-type arbor --report-period monthly --gap-min 10 --bps-unit Gbps
```

#### HTML-Only Mode (Regenerate HTML from existing CSV report)

```powershell
# Select from existing reports
python dfc_security_reporter.py --mode html-only --detector-type kentik

# Use a specific report CSV
python dfc_security_reporter.py --mode html-only --detector-type kentik --report-period weekly --report-csv Reports/Kentik_Radware_Campaigns_20260724_120000.csv
```

## Workflow

### For a Kentik External Detector

1. **Place forensic CSV/ZIP files** in `Inputs/Forensics Input/`
2. **Place DefenseFlow logs/ZIP files** in `Inputs/DefenseFlow Input/`
3. **Run the script**:
   ```powershell
  python dfc_security_reporter.py```
4. **Select options**:
  - External Detector Type: `1` (Kentik)
5. **Find your reports** in `Reports/` folder:
  - `Kentik_Radware_Campaigns_YYYYMMDD_HHMMSS.csv` (Campaign data)
  - `Kentik_Radware_Report_YYYYMMDD_HHMMSS.html` (Interactive HTML report)

### For an Arbor External Detector

1. **Place forensic CSV/ZIP files** in `Inputs/Forensics Input/`
2. **Place DefenseFlow logs/ZIP files** in `Inputs/DefenseFlow Input/`
3. **Run the script**:
   ```powershell
  python dfc_security_reporter.py```
4. **Select options**:
  - External Detector Type: `2` (Arbor)
5. **Find your reports** in `Reports/` folder

## Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `--mode` | `full` (process CSV) or `html-only` (regenerate HTML) |
| `--detector-type` | External detector: `kentik`, `arbor`, or `defensepro` |
| `--report-period` | Report period: `weekly` or `monthly` |
| `--input-dir` | Override the Forensics input directory |
| `--output-dir` | Override output directory (default: Reports/) |
| `--report-csv` | Existing report CSV for html-only mode |
| `--gap-min` | Time gap in minutes to group campaigns (default: 5) |
| `--time-format` | Input datetime format |
| `--bps-unit` | Bandwidth unit: `auto`, `Gbps`, `Mbps`, `Kbps`, `bps` |
| `--pps-unit` | Packet rate unit: `auto`, `Mpps`, `Kpps`, `pps` |
| `--title` | Custom report title |
| `--non-interactive` | Run without prompts (requires `--detector-type`) |

## HTML Report Features

The generated HTML report includes:

### Executive Overview
- Total attack campaigns
- Weekly or monthly periods analyzed
- Peak bandwidth and PPS (clickable for details)
- Most targeted IP address

### Period Trends
- Attack count per week or month
- Maximum bandwidth per week or month
- Maximum PPS per week or month
- Top destination IP hit count per week or month

### Attack Analysis
- Top attack vectors (pie chart)
- Risk level distribution (pie chart)

### Detailed Tables
- Top 10 attacks by bandwidth
- Weekly or monthly summary with:
  - Attack counts
  - Peak bandwidth and PPS
  - Most targeted IP per period
  - Longest attack duration

### Interactive Features
- Click on peak bandwidth/PPS cards for attack details
- Responsive charts using Chart.js
- Modal popups for detailed information
- Mobile-friendly design

### External Detector Analysis

Kentik, Arbor, and DefensePro reports use the DefenseFlow logs in `Inputs/DefenseFlow Input/` to produce:

- `{DetectorType}_Radware_Activations_{timestamp}.csv`
- `{DetectorType}_Radware_Raw_Events_{timestamp}.csv`
- `{DetectorType}_Radware_Attack_Cycles_{timestamp}.csv`
- A daily activation chart with a total activation field

DefenseFlow data is optional for the forensic campaign report. When DefenseFlow files are present, the tool adds detector activation and attack-cycle analysis. When they are absent, the forensic campaign and HTML report can still be generated from the forensic input alone.

## Output Files

All final reports are saved to `C:\your\path\Monthly_activity_report\Reports\`:

- **Campaign CSV**: `{DetectorType}_Radware_Campaigns_{timestamp}.csv`
  - The primary normalized campaign dataset.
  - Contains attack windows, duration, destination IP, event count, peak bandwidth, peak PPS, protocols, vectors, policies, devices, dropped packets, and risk.
  - Intended for detailed review, downstream analysis, auditing, and data exchange.

- **Activation CSV**: `{DetectorType}_Radware_Activations_{timestamp}.csv`
  - Daily count of detector activation events within the selected time filter. When `activation_operation` is configured, it follows the operation-based activation rule described above.
  - Intended to support daily activity measurement and validation of the activation chart.

- **Raw Events CSV**: `{DetectorType}_Radware_Raw_Events_{timestamp}.csv`
  - Parsed DefenseFlow start/end records before they are grouped into attack cycles.
  - Includes timestamp, event type, network, protocol, external detector ID, bandwidth, and original log text.
  - Intended for traceability, troubleshooting, and investigation of how an attack cycle was formed.

- **Attack Cycles CSV**: `{DetectorType}_Radware_Attack_Cycles_{timestamp}.csv`
  - One normalized row per unique external detector attack ID. This is intentionally independent from any operation-based activation count.
  - Includes status, target network, protocol, bandwidth, start/end timestamps, duration, detection source, and event count.
  - Intended for detector-level attack history and reconciliation with activation totals.

- **Interactive HTML Report**: `{DetectorType}_Radware_Report_{timestamp}.html`
  - Human-readable security report for operational review and sharing.
  - Includes executive metrics, attack trends, peak traffic details, destination analysis, attack vectors, weekly/monthly summaries, DefenseFlow activations, and detailed attack tables.
  - The report period controls the trend grouping; the date filter controls which events are included in the analysis.

## Examples

### Kentik Detector Report

```powershell
# Interactive
python dfc_security_reporter.py
# Select: 1 (Kentik external detector)

# Non-interactive
python dfc_security_reporter.py --detector-type kentik --non-interactive
```

### Arbor Detector Report

```powershell
python dfc_security_reporter.py --detector-type arbor --title "Arbor Report - July 2026"
```

### DefensePro Detector Report

```powershell
python dfc_security_reporter.py --detector-type defensepro --report-period monthly --non-interactive
```

### Regenerate HTML with Custom Units

```powershell
python dfc_security_reporter.py --mode html-only --report-csv Reports/existing_report.csv --bps-unit Mbps --pps-unit Kpps
```

## Troubleshooting

### No CSV files found
- Check that input files are in the correct folder:
  - Forensics data: `Inputs/Forensics Input/`
  - DefenseFlow data: `Inputs/DefenseFlow Input/`

### Column name errors
- Verify your CSV has required columns:
  - Start Time (or Start, Time Start)
  - End Time (or End, Time End)
  - Destination IP Address (or Destination IP, Dst IP)

### Encoding issues
- Set generic processing values in `dfc_security_reporter.ini`:
  ```ini
 [processing]
 time_format = %m/%d/%Y %H:%M:%S
  encoding = utf-8  # or latin1  ```

### Time format errors
- Update `time_format` in the `[processing]` section to match your CSV:
  ```ini
[processing]
  time_format = %m.%d.%Y %H:%M:%S```

## Notes

- The script automatically selects the most recent CSV file if no specific file is provided
- All configuration can be overridden via command-line arguments
- Reports include timestamps to prevent overwriting
- Generic processing settings in `dfc_security_reporter.ini` can be customized per deployment
- Interactive mode asks whether to generate a weekly or monthly report
