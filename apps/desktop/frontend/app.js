// Minimal workspace UI: task visibility over typed Tauri commands.
// No authorization logic lives here. Every action calls one Rust command;
// the Rust core decides. This file renders views, nothing more.

const goalInput = document.getElementById("goal");
const constraintsInput = document.getElementById("constraints");
const formError = document.getElementById("form-error");
const tasksList = document.getElementById("tasks");
const detail = document.getElementById("detail");

function showError(message) {
  formError.textContent = message;
}

// `window.__TAURI__` is injected only when `app.withGlobalTauri` is true in
// tauri.conf.json, and this is a classic script with no bundler, so there is
// no module import to fall back on. Without the bridge every flow below is
// inert, so say so in the page: reading `.core` off `undefined` would throw
// here and leave a window that renders correctly and answers nothing.
const bridge = window.__TAURI__;
if (!bridge?.core?.invoke) {
  showError(
    "Tauri bridge unavailable: window.__TAURI__.core.invoke is missing. " +
      "Set app.withGlobalTauri to true in tauri.conf.json and rebuild."
  );
  throw new Error("tauri bridge unavailable");
}
const { invoke } = bridge.core;

async function refreshTasks() {
  showError("");
  try {
    const tasks = await invoke("list_tasks");
    tasksList.innerHTML = "";
    for (const task of tasks) {
      const item = document.createElement("li");
      const open = document.createElement("button");
      open.textContent = `${task.id} — ${task.goal} [${task.state}]`;
      open.addEventListener("click", () => showDetail(task.id));
      const cancel = document.createElement("button");
      cancel.textContent = "Cancel";
      cancel.addEventListener("click", async () => {
        try {
          await invoke("cancel_task", { taskId: task.id });
          await refreshTasks();
        } catch (error) {
          showError(String(error));
        }
      });
      item.append(open, " ", cancel);
      tasksList.appendChild(item);
    }
    if (tasks.length === 0) {
      tasksList.innerHTML = "<li>No tasks yet.</li>";
    }
  } catch (error) {
    showError(String(error));
  }
}

async function showDetail(taskId) {
  try {
    const task = await invoke("query_task", { taskId });
    const contract = await invoke("inspect_contract", { taskId }).catch(() => null);
    detail.innerHTML = "";
    const title = document.createElement("h3");
    title.textContent = `${task.id} [${task.state}] rev ${task.revision}`;
    const goal = document.createElement("p");
    goal.textContent = task.goal;
    detail.append(title, goal);
    if (contract && contract.constraints.length > 0) {
      const list = document.createElement("ul");
      for (const constraint of contract.constraints) {
        const entry = document.createElement("li");
        entry.textContent = constraint;
        list.appendChild(entry);
      }
      const heading = document.createElement("h4");
      heading.textContent = "Constraints";
      detail.append(heading, list);
    }
  } catch (error) {
    showError(String(error));
  }
}

document.getElementById("submit").addEventListener("click", async () => {
  showError("");
  const constraints = constraintsInput.value
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  try {
    await invoke("submit_goal", { goal: goalInput.value, constraints });
    goalInput.value = "";
    constraintsInput.value = "";
    await refreshTasks();
  } catch (error) {
    showError(String(error));
  }
});

document.getElementById("refresh").addEventListener("click", refreshTasks);

refreshTasks();
