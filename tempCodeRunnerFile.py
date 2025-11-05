# Simple Study Task Planner (Flexible Version)

# Step 1: Take number of tasks
num = input("📘 Enter number of study tasks: ")

# Convert safely to int
if not num.isdigit():
    print("⚠️ Invalid input. Defaulting to 3 tasks.")
    num = 3
else:
    num = int(num)

# Step 2: Empty list to store tasks
tasks = []

# Step 3: Input tasks
for i in range(num):
    name = input(f"📝 Task {i+1} name: ")
    priority = input("   🔢 Priority (High / Medium / Low / anything): ").strip().lower()

    # Map to numbers (for sorting)
    if priority in ["1", "high", "h"]:
        priority_val = 1
    elif priority in ["2", "medium", "m"]:
        priority_val = 2
    elif priority in ["3", "low", "l"]:
        priority_val = 3
    else:
        priority_val = 4  # for unknown words

    tasks.append({"task": name, "priority": priority_val, "priority_text": priority})

# Step 4: Sort by priority
tasks.sort(key=lambda x: x["priority"])

# Step 5: Show plan
print("\n📋 Sorted Study Plan (by Priority):")
for t in tasks:
    level = (
        "High" if t["priority"] == 1 else
        "Medium" if t["priority"] == 2 else
        "Low" if t["priority"] == 3 else
        t["priority_text"].capitalize()
    )
    print(f"- {t['task']} ({level} Priority)")
