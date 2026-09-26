// 打桩 API：仅供本地渲染验证（不参与正式构建）
// 与 internal/gui.Service 的绑定结构一致，数据模拟 seed 库场景。
window.runtime = {
  WindowMinimise: function () {},
  WindowToggleMaximise: function () {},
  Quit: function () {},
  WindowSetSize: function () {},
  WindowCenter: function () {}
};
window.go = { gui: { Service: {
  InitState: function () { return Promise.resolve({ vaultExists: true, path: 'C:\\mock\\vault.vault' }); },
  SetAuthWindow: function () { return Promise.resolve(); },
  SetMainWindow: function () { return Promise.resolve(); },
  StartDrag: function () { return Promise.resolve(); },
  DragBy: function () { return Promise.resolve(); },
  List: function () { return Promise.resolve([
    { id: '11111111111111111111111111111111', title: '生产数据库', username: 'dbadmin', address: '192.168.1.10', createdAt: 1758672000, deleted: false },
    { id: '22222222222222222222222222222222', title: 'VPN网关', username: 'vpn', address: '', createdAt: 1758672000, deleted: false }
  ]); },
  ListDeleted: function () { return Promise.resolve([]); },
  Get: function (id) { return Promise.resolve({
    id: id, title: '生产数据库', username: 'dbadmin', address: '192.168.1.10',
    port: 3306, note: '生产环境', password: 'P@ssw0rd#2026', createdAt: 1758672000, deleted: false
  }); },
  CopyPassword: function () { return Promise.resolve(); },
  Lock: function () { return Promise.resolve(); },
  AddFull: function (title, username, password, address, port, note) {
    return Promise.resolve({ id: '33333333333333333333333333333333', title: title, username: username, address: address, createdAt: 1758673000, deleted: false });
  },
  Update: function (id, title, username, password, address, port, note) {
    return Promise.resolve({ id: id, title: title, username: username, address: address, createdAt: 1758672000, deleted: false });
  },
  ChangeMasterPassword: function () { return Promise.resolve(); },
  Backup: function () { return Promise.resolve(); },
  RestoreFromBackup: function () { return Promise.reject(new Error('mock')); }
} } };
