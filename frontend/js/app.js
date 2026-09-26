// password-vault 前端逻辑：调用 Wails 绑定的后端服务（window.go.gui.Service）。
'use strict';

var api = window.go.gui.Service;

// ---------- 状态 ----------
var state = {
  allEntries: [],       // 全量列表快照（含回收站条目，搜索过滤的基准）
  entries: [],          // 当前视图列表（搜索过滤结果）
  selectedId: null,     // 当前选中条目 ID
  detail: null,         // 当前详情（含密码明文）
  showPass: false,      // 详情密码是否明文显示
  view: 'normal',       // 'normal' 正常列表 / 'trash' 回收站
  unlocked: false
};

// ---------- DOM ----------
function $(id) { return document.getElementById(id); }
var lockScreen = $('screen-lock'),
    mainScreen = $('screen-main'),
    lockMode = $('lock-mode'),
    createMode = $('create-mode'),
    entryList = $('entry-list'),
    detailBody = $('detail-body'),
    detailEmpty = $('detail-empty'),
    toastEl = $('toast');

function errMsg(e) {
  if (!e) return '操作失败';
  if (typeof e === 'string') return e;
  if (e.message) return e.message;
  return String(e);
}

function toast(msg, ms) {
  toastEl.textContent = msg;
  toastEl.classList.remove('hidden');
  clearTimeout(toastEl._t);
  toastEl._t = setTimeout(function () { toastEl.classList.add('hidden'); }, ms || 2600);
}

// ---------- 启动 ----------
api.InitState().then(function (st) {
  // 登录/创建阶段：窗口缩成小框（类似微信/飞书登录窗口）。
  api.SetAuthWindow();
  if (st.vaultExists) { lockMode.classList.remove('hidden'); createMode.classList.add('hidden'); }
  else { lockMode.classList.add('hidden'); createMode.classList.remove('hidden'); }
}).catch(function (e) { toast('初始化失败：' + errMsg(e)); });

// ---------- 解锁 / 创建 ----------
$('lock-submit').addEventListener('click', unlock);
$('lock-pass').addEventListener('keydown', function (ev) { if (ev.key === 'Enter') unlock(); });

// 解锁失败退避倒计时：连续输错后按钮与输入框禁用，显示剩余等待秒数。
var lockCooldownTimer = null;
function startCooldown(seconds) {
  var btn = $('lock-submit'), inp = $('lock-pass');
  btn.disabled = true;
  inp.disabled = true;
  var left = seconds;
  btn.textContent = left + ' 秒后重试';
  clearInterval(lockCooldownTimer);
  lockCooldownTimer = setInterval(function () {
    left--;
    if (left <= 0) {
      clearInterval(lockCooldownTimer);
      btn.disabled = false;
      inp.disabled = false;
      btn.textContent = '解锁';
    } else {
      btn.textContent = left + ' 秒后重试';
    }
  }, 1000);
}

// loadAll 取全量快照（正常列表 + 回收站），供搜索与视图切换使用。
function loadAll() {
  return Promise.all([api.List(), api.ListDeleted()]).then(function (r) {
    state.allEntries = r[0].concat(r[1]);
  });
}

function unlock() {
  var pass = $('lock-pass').value;
  if (!pass) { toast('请输入主密码'); return; }
  api.Unlock(pass).then(function () {
    state.unlocked = true;
    state.view = 'normal';
    state.selectedId = null;
    state.detail = null;
    return loadAll();
  }).then(function () {
    doSearch('');
    mainScreen.classList.remove('hidden');
    lockScreen.classList.add('hidden');
    showDetailEmpty();
    refreshTrashCount();
    api.SetMainWindow(); // 解锁成功：窗口恢复主界面尺寸
  }).catch(function (e) {
    var msg = errMsg(e);
    toast('解锁失败：' + msg);
    $('lock-pass').value = '';
    var m = msg.match(/请 (\d+) 秒/);
    if (m) startCooldown(parseInt(m[1], 10));
  });
}

$('create-submit').addEventListener('click', createVault);
['create-pass', 'create-pass2'].forEach(function (id) {
  $(id).addEventListener('keydown', function (ev) { if (ev.key === 'Enter') createVault(); });
});

function createVault() {
  var p1 = $('create-pass').value,
      p2 = $('create-pass2').value;
  var weak = strengthError(p1);
  if (weak) { toast(weak); return; }
  if (p1 !== p2) { toast('两次输入的主密码不一致'); return; }
  api.CreateVault(p1).then(function () {
    // 创建成功后自动解锁进入主界面。
    return api.Unlock(p1);
  }).then(function () {
    state.unlocked = true;
    return loadAll();
  }).then(function () {
    doSearch('');
    mainScreen.classList.remove('hidden');
    lockScreen.classList.add('hidden');
    showDetailEmpty();
    refreshTrashCount();
    api.SetMainWindow(); // 创建成功并解锁：窗口恢复主界面尺寸
    toast('保险箱已创建');
  }).catch(function (e) { toast('创建失败：' + errMsg(e)); });
}

// 密码可见性切换（解锁屏与创建屏）。
$('lock-toggle').addEventListener('click', function () {
  var inp = $('lock-pass');
  inp.type = inp.type === 'password' ? 'text' : 'password';
  this.textContent = inp.type === 'password' ? '显示' : '隐藏';
});

// 主密码强度校验（与后端 internal/policy 一致：≥12 位且四类字符至少三类）。
function strengthError(p) {
  if (p.length < 12) return '主密码至少 12 位';
  var cls = 0;
  if (/[a-z]/.test(p)) cls++;
  if (/[A-Z]/.test(p)) cls++;
  if (/\d/.test(p)) cls++;
  if (/[^a-zA-Z0-9]/.test(p)) cls++;
  if (cls < 3) return '主密码需包含大写、小写、数字、符号中的至少三类';
  return '';
}
document.querySelectorAll('.toggle-pass').forEach(function (btn) {
  btn.addEventListener('click', function () {
    var inp = $(this.dataset.target);
    inp.type = inp.type === 'password' ? 'text' : 'password';
    this.textContent = inp.type === 'password' ? '显示' : '隐藏';
  });
});

// ---------- 列表 ----------
function renderList() {
  entryList.innerHTML = '';
  var count = 0;
  state.entries.forEach(function (e) {
    count++;
    var li = document.createElement('li');
    li.className = 'item' + (e.id === state.selectedId ? ' sel' : '');
    var av = document.createElement('span');
    av.className = 'av';
    av.textContent = (e.title || '?').charAt(0).toUpperCase();
    var tx = document.createElement('span');
    tx.className = 'item-text';
    var t = document.createElement('span'); t.className = 'item-title'; t.textContent = e.title;
    var u = document.createElement('span'); u.className = 'item-user'; u.textContent = e.address ? e.username + ' · ' + e.address : e.username;
    tx.appendChild(t); tx.appendChild(u);
    li.appendChild(av); li.appendChild(tx);
    li.addEventListener('click', function () { selectEntry(e.id); });
    entryList.appendChild(li);
  });
  $('entry-count').textContent = '共 ' + count + ' 条凭据';
}

function selectEntry(id) {
  resetDeleteArm();
  resetPurgeArm();
  // 空 ID（如当前列表为空）不发起后端查询，避免"无效的凭据 ID"误报。
  if (!id) { showDetailEmpty(); return; }
  state.selectedId = id;
  state.showPass = false;
  renderList();
  api.Get(id).then(function (d) {
    state.detail = d;
    renderDetail();
  }).catch(function (e) { toast('读取失败：' + errMsg(e)); });
}

// ---------- 详情 ----------
function showDetailEmpty() {
  detailBody.classList.add('hidden');
  detailEmpty.classList.remove('hidden');
}

function renderDetail() {
  var d = state.detail;
  if (!d) { showDetailEmpty(); return; }
  detailEmpty.classList.add('hidden');
  detailBody.classList.remove('hidden');
  $('d-title').textContent = d.title;
  $('d-username').textContent = d.username;
  $('d-field-address').classList.toggle('hidden', !d.address);
  if (d.address) $('d-address').textContent = d.address;
  $('d-field-port').classList.toggle('hidden', !d.port);
  if (d.port) $('d-port').textContent = d.port;
  $('d-field-note').classList.toggle('hidden', !d.note);
  if (d.note) $('d-note').textContent = d.note;
  var trash = state.view === 'trash';
  $('d-edit').classList.toggle('hidden', trash);
  $('d-field-pass').classList.toggle('hidden', trash);      // 回收站条目不显示/复制密码
  $('d-ops-trash').classList.toggle('hidden', !trash);      // 回收站操作：恢复/彻底删除
  $('d-delete').classList.toggle('hidden', trash);          // 正常视图操作：删除
  if (!trash) updatePasswordView();
  var dt = new Date(d.createdAt * 1000);
  $('d-created').textContent = '创建时间：' + dt.getFullYear() + '-' +
    String(dt.getMonth() + 1).padStart(2, '0') + '-' + String(dt.getDate()).padStart(2, '0');
}

function updatePasswordView() {
  $('d-password').textContent = state.showPass ? state.detail.password : '••••••••••••';
  $('d-toggle').textContent = state.showPass ? '隐藏' : '显示';
}

$('d-toggle').addEventListener('click', function () {
  state.showPass = !state.showPass;
  updatePasswordView();
});

$('d-copy').addEventListener('click', function () {
  if (!state.detail) return;
  api.CopyPassword(state.detail.id).then(function () {
    toast('密码已复制，30 秒后自动清空剪贴板');
  }).catch(function (e) { toast('复制失败：' + errMsg(e)); });
});

$('d-edit').addEventListener('click', function () {
  if (!state.detail) return;
  openModal(state.detail);
});

// ---------- 删除 / 回收站 ----------
// 删除（软删除）：移入回收站，可恢复；彻底删除在回收站视图中进行。
var deleteArmed = false, deleteTimer = null;
function resetDeleteArm() {
  if (deleteArmed) {
    clearTimeout(deleteTimer);
    deleteArmed = false;
    $('d-delete').textContent = '删除凭据';
    $('d-delete').classList.remove('armed');
  }
}
$('d-delete').addEventListener('click', function () {
  if (!state.detail) return;
  if (!deleteArmed) {
    deleteArmed = true;
    this.textContent = '确认删除？';
    this.classList.add('armed');
    deleteTimer = setTimeout(resetDeleteArm, 3000);
    return;
  }
  var id = state.detail.id;
  resetDeleteArm();
  api.Remove(id).then(function () { return loadAll(); }).then(function () {
    state.detail = null;
    state.selectedId = null;
    doSearch($('search').value);
    showDetailEmpty();
    refreshTrashCount();
    toast('已移入回收站');
  }).catch(function (e) { toast('删除失败：' + errMsg(e)); });
});

// 回收站视图切换（低调入口，点击切换 正常列表/回收站）。
function refreshTrashCount() {
  if (!state.unlocked) { $('trash-count').textContent = ''; return; }
  api.ListDeleted().then(function (list) {
    $('trash-count').textContent = list.length ? list.length : '';
  }).catch(function () {});
}
$('btn-trash').addEventListener('click', function () {
  state.view = state.view === 'trash' ? 'normal' : 'trash';
  $('btn-trash').classList.toggle('on', state.view === 'trash');
  state.selectedId = null;
  state.detail = null;
  resetDeleteArm();
  resetPurgeArm();
  doSearch($('search').value);
  showDetailEmpty();
});

// 恢复凭据。
$('d-restore').addEventListener('click', function () {
  if (!state.detail) return;
  var id = state.detail.id;
  api.Restore(id).then(function () { return loadAll(); }).then(function () {
    state.view = 'normal';
    $('btn-trash').classList.remove('on');
    state.detail = null;
    state.selectedId = null;
    doSearch('');
    showDetailEmpty();
    refreshTrashCount();
    toast('凭据已恢复');
  }).catch(function (e) { toast('恢复失败：' + errMsg(e)); });
});

// 彻底删除（二次确认；触发密文覆盖）。
var purgeArmed = false, purgeTimer = null;
function resetPurgeArm() {
  if (purgeArmed) {
    clearTimeout(purgeTimer);
    purgeArmed = false;
    $('d-purge').textContent = '彻底删除';
    $('d-purge').classList.remove('armed');
  }
}
$('d-purge').addEventListener('click', function () {
  if (!state.detail) return;
  if (!purgeArmed) {
    purgeArmed = true;
    this.textContent = '确认彻底删除？';
    this.classList.add('armed');
    purgeTimer = setTimeout(resetPurgeArm, 3000);
    return;
  }
  var id = state.detail.id;
  resetPurgeArm();
  api.Purge(id).then(function () { return loadAll(); }).then(function () {
    state.detail = null;
    state.selectedId = null;
    doSearch($('search').value);
    showDetailEmpty();
    refreshTrashCount();
    toast('已彻底删除，密文已覆盖');
  }).catch(function (e) { toast('彻底删除失败：' + errMsg(e)); });
});

// ---------- 搜索 ----------
// 中文输入法（IME）组合期间不触发过滤，避免拼音中间态导致列表闪空；
// 过滤始终基于全量快照 allEntries，删除字符时被过滤掉的条目能正确恢复；
// 按当前视图（正常/回收站）过滤。
var searchComposing = false;
function doSearch(q) {
  q = (q || '').trim().toLowerCase();
  var src = state.allEntries.filter(function (e) {
    return state.view === 'trash' ? e.deleted : !e.deleted;
  });
  if (!q) {
    state.entries = src;
    renderList();
    return;
  }
  state.entries = src.filter(function (e) {
    return e.title.toLowerCase().indexOf(q) >= 0 || e.username.toLowerCase().indexOf(q) >= 0;
  });
  renderList();
}
$('search').addEventListener('compositionstart', function () { searchComposing = true; });
$('search').addEventListener('compositionend', function () { searchComposing = false; doSearch(this.value); });
$('search').addEventListener('input', function () { if (!searchComposing) doSearch(this.value); });

// ---------- 新增弹窗 ----------
function openModal(entry) {
  state.editingId = entry ? entry.id : null;
  $('add-head').childNodes[0].nodeValue = entry ? '编辑凭据' : '添加凭据';
  $('add-title').value = entry ? entry.title : '';
  $('add-username').value = entry ? entry.username : '';
  $('add-address').value = entry ? (entry.address || '') : '';
  $('add-port').value = entry && entry.port ? String(entry.port) : '';
  $('add-note').value = entry ? (entry.note || '') : '';
  $('add-password').value = '';
  $('modal-add').classList.remove('hidden');
  $('add-title').focus();
}
function closeModal() {
  state.editingId = null;
  $('modal-add').classList.add('hidden');
  ['add-title', 'add-username', 'add-address', 'add-port', 'add-note', 'add-password'].forEach(function (id) { $(id).value = ''; });
}
$('btn-add').addEventListener('click', function () { openModal(); });
$('add-close').addEventListener('click', closeModal);
$('add-cancel').addEventListener('click', closeModal);
$('modal-add').addEventListener('click', function (ev) { if (ev.target === this) closeModal(); });

$('add-save').addEventListener('click', saveEntry);
['add-title', 'add-username', 'add-address', 'add-port', 'add-note', 'add-password'].forEach(function (id) {
  $(id).addEventListener('keydown', function (ev) { if (ev.key === 'Enter') saveEntry(); });
});

function saveEntry() {
  var title = $('add-title').value.trim(),
      username = $('add-username').value.trim(),
      address = $('add-address').value.trim(),
      portText = $('add-port').value.trim(),
      note = $('add-note').value.trim(),
      password = $('add-password').value;
  if (!title || !username || !password) { toast('标题、账号、密码均不能为空'); return; }
  var port = 0;
  if (portText) {
    if (!/^\d{1,5}$/.test(portText)) { toast('端口需为 0–65535 的数字'); return; }
    port = parseInt(portText, 10);
    if (port > 65535) { toast('端口需为 0–65535 的数字'); return; }
  }
  var req = state.editingId
    ? api.Update(state.editingId, title, username, password, address, port, note)
    : api.AddFull(title, username, password, address, port, note);
  req.then(function (view) {
    var editing = state.editingId != null;
    closeModal();
    // 编辑：替换快照中同 ID 条目；新增：并入快照（不依赖搜索框/当前视图过滤结果）。
    var exists = false;
    state.allEntries = state.allEntries.map(function (e) {
      if (e.id === view.id) { exists = true; return view; }
      return e;
    });
    if (!exists) state.allEntries.push(view);
    state.allEntries.sort(function (a, b) { return b.createdAt - a.createdAt; });
    if (!editing && state.view !== 'normal') {
      state.view = 'normal';
      $('btn-trash').classList.remove('on');
    }
    doSearch($('search').value);
    selectEntry(view.id);
    refreshTrashCount();
    toast(editing ? '凭据已更新' : '凭据已保存');
  }).catch(function (e) { toast('保存失败：' + errMsg(e)); });
}

// ---------- 锁定 / 自动锁定 ----------

// lockNow 统一锁定流程：清空内存态、切回解锁屏、窗口缩回小框。
function lockNow(msg) {
  api.Lock();
  state.unlocked = false;
  state.entries = [];
  state.allEntries = [];
  state.selectedId = null;
  state.detail = null;
  state.view = 'normal';
  $('btn-trash').classList.remove('on');
  $('trash-count').textContent = '';
  mainScreen.classList.add('hidden');
  lockScreen.classList.remove('hidden');
  $('lock-pass').value = '';
  api.SetAuthWindow();
  if (msg) toast(msg);
}

$('btn-lock').addEventListener('click', function () { lockNow(); });

// 闲置自动锁定：解锁后长时间无操作自动锁定（等保"身份鉴别"的会话超时要求）。
// 默认 5 分钟；可配置项留待「设置」功能落地时提供入口。
var AUTO_LOCK_MS = 5 * 60 * 1000;
var lastActivity = Date.now();
['mousedown', 'keydown', 'input', 'scroll', 'touchstart'].forEach(function (ev) {
  document.addEventListener(ev, function () { lastActivity = Date.now(); }, { passive: true });
});
setInterval(function () {
  if (!state.unlocked) return;
  if (Date.now() - lastActivity >= AUTO_LOCK_MS) {
    lockNow('长时间未操作，已自动锁定');
  }
}, 10000);

// 备份：将库文件整体备份为带完整性校验的密文副本（系统对话框选位置）。
$('btn-backup').addEventListener('click', function () {
  if (!state.unlocked) return;
  api.Backup().then(function () { toast('备份已保存'); })
    .catch(function (e) { toast(errMsg(e)); });
});

// 恢复：校验备份完整性后覆盖当前库，需重新解锁（二次确认，防误操作）。
var restoreArmed = false, restoreTimer = null;
function resetRestoreArm() {
  if (restoreArmed) {
    clearTimeout(restoreTimer);
    restoreArmed = false;
    $('btn-restore').textContent = '恢复';
    $('btn-restore').classList.remove('armed');
  }
}
$('btn-restore').addEventListener('click', function () {
  if (!state.unlocked) return;
  if (!restoreArmed) {
    restoreArmed = true;
    this.textContent = '确认恢复？';
    this.classList.add('armed');
    restoreTimer = setTimeout(resetRestoreArm, 4000);
    return;
  }
  resetRestoreArm();
  api.RestoreFromBackup().then(function () {
    lockNow();
    toast('备份已恢复，请重新解锁');
  }).catch(function (e) { toast('恢复失败：' + errMsg(e)); });
});

// ---------- 设置：修改主密码 ----------
function openSettings() {
  $('modal-settings').classList.remove('hidden');
  $('set-old').focus();
}
function closeSettings() {
  $('modal-settings').classList.add('hidden');
  ['set-old', 'set-new', 'set-new2'].forEach(function (id) { $(id).value = ''; });
}
$('btn-settings').addEventListener('click', function () { if (!state.unlocked) return; openSettings(); });
$('set-close').addEventListener('click', closeSettings);
$('set-cancel').addEventListener('click', closeSettings);
$('modal-settings').addEventListener('click', function (ev) { if (ev.target === this) closeSettings(); });

function saveSettings() {
  var oldPass = $('set-old').value,
      newPass = $('set-new').value,
      newPass2 = $('set-new2').value;
  if (!oldPass || !newPass || !newPass2) { toast('请填写完整'); return; }
  if (newPass !== newPass2) { toast('两次输入的新密码不一致'); return; }
  api.ChangeMasterPassword(oldPass, newPass).then(function () {
    closeSettings();
    toast('主密码已修改');
  }).catch(function (e) { toast('修改失败：' + errMsg(e)); });
}
$('set-save').addEventListener('click', saveSettings);
['set-old', 'set-new', 'set-new2'].forEach(function (id) {
  $(id).addEventListener('keydown', function (ev) { if (ev.key === 'Enter') saveSettings(); });
});

// ---------- 自绘标题栏：窗口控制（无边框窗口） ----------
$('tb-min').addEventListener('click', function () { window.runtime.WindowMinimise(); });
$('tb-max').addEventListener('click', function () { window.runtime.WindowToggleMaximise(); });
$('tb-close').addEventListener('click', function () { window.runtime.Quit(); });

// 无边框窗口拖动：Wails 不支持 CSS app-region 拖拽，改为按下标题栏后按增量移动窗口。
var dragActive = false;
$('titlebar').addEventListener('mousedown', function (e) {
  if (e.target.closest('.tb-actions')) return; // 按钮区不触发拖动
  if (e.button !== 0) return;
  dragActive = true;
  api.StartDrag();
  e.preventDefault();
});
document.addEventListener('mousemove', function (e) {
  if (!dragActive) return;
  api.DragBy(e.movementX, e.movementY);
});
document.addEventListener('mouseup', function () { dragActive = false; });
