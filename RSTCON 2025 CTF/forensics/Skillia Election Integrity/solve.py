import pandas as pd
import numpy as np

def analyze_election_fraud(file_path):
    """
    Analyzes voting data to identify 6 manipulated polling stations.

    Args:
        file_path (str): The path to the CSV file containing voting records.

    Returns:
        list: A list of the six most suspicious voting station IDs.
    """
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found. Ensure it is in the same directory as the script.")
        return None

    # Get a list of all unique voting station IDs
    all_stations = df['voting_station_id'].unique()
    suspicion_scores = pd.Series(0, index=all_stations, dtype=int)

    # --- ANALYSIS 1: Extreme Presidential Vote Shares ---
    # In a tight election, results >95% or <5% for one candidate are highly improbable.
    presidential_votes = df.groupby('voting_station_id')['vote_president'].value_counts().unstack(fill_value=0)
    if 'A' in presidential_votes.columns and 'B' in presidential_votes.columns:
        presidential_votes['total'] = presidential_votes['A'] + presidential_votes['B']
        presidential_votes['A_percent'] = presidential_votes['A'] / presidential_votes['total']
        extreme_votes = presidential_votes[
            (presidential_votes['A_percent'] > 0.95) | (presidential_votes['A_percent'] < 0.05)
        ]
        for station in extreme_votes.index:
            suspicion_scores[station] += 1
        print(f"Found suspicious stations based on presidential results: {len(extreme_votes.index)}")

    # --- ANALYSIS 2: Anomalous Undervote Rates ---
    # A zero undervote rate is suspicious, as are abnormally high rates (>20%).
    governor_votes = df.groupby('voting_station_id')['vote_governor'].value_counts().unstack(fill_value=0)
    governor_votes['total'] = governor_votes.sum(axis=1)
    if 'undervote' in governor_votes.columns:
        governor_votes['undervote_rate'] = governor_votes['undervote'] / governor_votes['total']
        anomalous_undervotes = governor_votes[
            (governor_votes['undervote_rate'] == 0) | (governor_votes['undervote_rate'] > 0.20)
        ]
        for station in anomalous_undervotes.index:
            suspicion_scores[station] += 1
        print(f"Found suspicious stations based on undervotes: {len(anomalous_undervotes.index)}")

    # --- ANALYSIS 3: In-Person vs. Absentee Discrepancy ---
    # A large split (>50%) in vote choice between in-person and absentee voters is a red flag.
    type_comparison = df.groupby(['voting_station_id', 'voter_type'])['vote_president'].value_counts().unstack(fill_value=0)
    if 'A' in type_comparison.columns and 'B' in type_comparison.columns:
        type_comparison['total'] = type_comparison['A'] + type_comparison['B']
        type_comparison['A_percent'] = type_comparison['A'] / type_comparison['total']
        split = type_comparison.reset_index().pivot(index='voting_station_id', columns='voter_type', values='A_percent')
        if 'in_person' in split.columns and 'absentee' in split.columns:
            split['discrepancy'] = abs(split['in_person'] - split['absentee'])
            large_discrepancy = split[split['discrepancy'] > 0.5]
            for station in large_discrepancy.index:
                suspicion_scores[station] += 1
            print(f"Found suspicious stations based on in-person/absentee split: {len(large_discrepancy.index)}")

    # --- ANALYSIS 4: Anomalous Turnout ---
    # Use the Interquartile Range (IQR) method to detect statistical outliers in total votes cast.
    turnout = df['voting_station_id'].value_counts()
    Q1, Q3 = turnout.quantile(0.25), turnout.quantile(0.75)
    IQR = Q3 - Q1
    lower_bound, upper_bound = Q1 - 1.5 * IQR, Q3 + 1.5 * IQR
    anomalous_turnout = turnout[(turnout < lower_bound) | (turnout > upper_bound)]
    for station in anomalous_turnout.index:
        suspicion_scores[station] += 1
    print(f"Found suspicious stations based on turnout: {len(anomalous_turnout.index)}")

    # --- FINAL TALLY ---
    # Sort stations by their suspicion score to find the top 6.
    top_6_suspicious = suspicion_scores.nlargest(6)
    print("\n--- Analysis Results ---")
    print("Suspicion scores for top stations:")
    print(top_6_suspicious)
    
    return top_6_suspicious.index.tolist()

if __name__ == "__main__":
    csv_file = 'skillia_voting_records.csv'
    manipulated_stations = analyze_election_fraud(csv_file)
    if manipulated_stations:
        result_string = ','.join(manipulated_stations)
        print("\nThe six most likely manipulated stations are:")
        print(f"MetaCTF{{{result_string}}}")