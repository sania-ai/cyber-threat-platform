
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path


def create_charts():

    input_file = Path("data/processed/cleaned_urls.csv")
    output_folder = Path("data/processed/charts")

    output_folder.mkdir(parents=True, exist_ok=True)

    if not input_file.exists():
        print("ERROR: Cleaned dataset not found.")
        return

    df = pd.read_csv(input_file)

    if df.empty:
        print("Dataset is empty.")
        return

    # Chart 1: Online vs Offline URLs
    status_counts = df["url_status"].value_counts()

    plt.figure(figsize=(8, 5))
    status_counts.plot(kind="bar")

    plt.title("URL Status Distribution")
    plt.xlabel("URL Status")
    plt.ylabel("Number of URLs")
    plt.xticks(rotation=0)
    plt.tight_layout()

    plt.savefig(output_folder / "url_status.png")
    plt.close()

    # Chart 2: Top 10 Hosts
    top_hosts = df["host"].value_counts().head(10)

    plt.figure(figsize=(10, 6))
    top_hosts.plot(kind="bar")

    plt.title("Top 10 Hosts")
    plt.xlabel("Host")
    plt.ylabel("Number of URLs")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    plt.savefig(output_folder / "top_hosts.png")
    plt.close()

    # Chart 3: URLs added over time
    df["date_added"] = pd.to_datetime(
        df["date_added"],
        errors="coerce",
        utc=True
    )

    daily_counts = (
        df.dropna(subset=["date_added"])
        .set_index("date_added")
        .resample("D")
        .size()
    )

    plt.figure(figsize=(10, 5))
    daily_counts.plot(kind="line", marker="o")

    plt.title("URLs Added Over Time")
    plt.xlabel("Date")
    plt.ylabel("Number of URLs")
    plt.tight_layout()

    plt.savefig(output_folder / "url_trends.png")
    plt.close()

    print("Charts created successfully!")
    print("Saved in:", output_folder)


if __name__ == "__main__":
    create_charts()
