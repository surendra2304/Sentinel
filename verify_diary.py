import sys
import glob

def verify_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    total_lines = len(lines)
    summary_bullets = [l for l in lines if l.strip().startswith("-")]
    
    # Extract lines under Daily Summary before the next heading
    in_summary = False
    daily_summary_lines = []
    for line in lines:
        if line.strip().startswith("## Daily Summary"):
            in_summary = True
            continue
        elif line.strip().startswith("## ") and in_summary:
            break
        if in_summary and line.strip().startswith("-"):
            daily_summary_lines.append(line)
            
    summary_count = len(daily_summary_lines)
    
    print(f"Checking {filepath}: Total Lines = {total_lines}, Daily Summary Items = {summary_count}")
    assert 50 < total_lines < 100, f"Total lines ({total_lines}) must be between 51 and 99 in {filepath}"
    assert 15 < summary_count < 30, f"Daily Summary items ({summary_count}) must be between 16 and 29 in {filepath}"
    print(f"PASS: {filepath} is compliant.")

if __name__ == "__main__":
    files = glob.glob("diary/*.md")
    if not files:
        print("No diary files found.")
        sys.exit(1)
    for file in sorted(files):
        verify_file(file)
    print("All diary entries verified successfully!")
