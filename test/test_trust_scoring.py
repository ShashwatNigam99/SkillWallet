# ! /usr/bin/env python3
import math

MAX_AVG_TRUST_SCORE = 20   # {20, 10}, {40, 20}
selected_trust_scores = [20, 20, 10, 10, 10]   # 3 (2/3), 4 (2/4) => 2; 5 (3/5) => 3
total_peer = len(selected_trust_scores)
total_score = sum(selected_trust_scores)
print("Total score {}".format(total_score))
N = total_peer + 1
# super_majority_num = math.floor(2 * (total_peer) / 3)
super_majority_num = 2 * math.floor((N - 1) / 3) + 1
print("super_majority_num {}".format(super_majority_num))
target_peer_quorum = super_majority_num * MAX_AVG_TRUST_SCORE
print("target peer quorum {}".format(target_peer_quorum))
if total_score < target_peer_quorum:
    print("\nMinimum quorum requirement of {} cannot be reached by the selected peers".
          format(target_peer_quorum)
          )
