/// Lua GUI bindings — create Qt6 widgets from Lua.
/// Supports: createForm, createButton, createLabel, createEdit, createCheckBox, createListView, createTimer
/// Property access via __index/__newindex metamethods.

#include "scripting/lua_gui.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <QWidget>
#include <QDialog>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#include <QListWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QApplication>
#include <QMetaObject>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <string>

namespace ce {

struct CallbackBinding {
    int ref = LUA_NOREF;
    QMetaObject::Connection connection;
};

// Store Lua callback references per Qt object.
static std::unordered_map<QObject*, CallbackBinding> clickCallbacks;
static std::unordered_map<QObject*, CallbackBinding> changeCallbacks;
static std::unordered_map<QObject*, CallbackBinding> closeCallbacks;
static std::unordered_map<QObject*, CallbackBinding> timerCallbacks;
static lua_State* guiLuaState = nullptr;

// ── Widget userdata wrapper ──

struct LuaWidget {
    QWidget* widget;
    QTimer* timer; // Non-null only for timer objects
};

static const char* WIDGET_MT = "CEWidget";

static LuaWidget* checkWidget(lua_State* L, int idx) {
    return (LuaWidget*)luaL_checkudata(L, idx, WIDGET_MT);
}

static void pushWidget(lua_State* L, QWidget* w, QTimer* t = nullptr) {
    auto* lw = (LuaWidget*)lua_newuserdata(L, sizeof(LuaWidget));
    lw->widget = w;
    lw->timer = t;
    luaL_setmetatable(L, WIDGET_MT);
}

static void unrefCallback(int ref) {
    if (guiLuaState && ref != LUA_NOREF && ref != LUA_REFNIL)
        luaL_unref(guiLuaState, LUA_REGISTRYINDEX, ref);
}

static void clearCallback(QObject* object, std::unordered_map<QObject*, CallbackBinding>& callbacks) {
    auto it = callbacks.find(object);
    if (it == callbacks.end())
        return;
    QObject::disconnect(it->second.connection);
    unrefCallback(it->second.ref);
    callbacks.erase(it);
}

static int storeCallback(lua_State* L, int index) {
    lua_pushvalue(L, index);
    return luaL_ref(L, LUA_REGISTRYINDEX);
}

static void invokeLuaCallback(int ref, QWidget* widget, QTimer* timer = nullptr) {
    if (!guiLuaState)
        return;

    lua_rawgeti(guiLuaState, LUA_REGISTRYINDEX, ref);
    if (widget)
        pushWidget(guiLuaState, widget, timer);
    else
        lua_pushnil(guiLuaState);
    if (lua_pcall(guiLuaState, 1, 0, 0) != LUA_OK) {
        const char* err = lua_tostring(guiLuaState, -1);
        std::fprintf(stderr, "[CE Lua GUI] callback error: %s\n", err ? err : "unknown error");
        lua_pop(guiLuaState, 1);
    }
}

static void trackDestroyed(QObject* object) {
    QObject::connect(object, &QObject::destroyed, [object]() {
        clearCallback(object, clickCallbacks);
        clearCallback(object, changeCallbacks);
        clearCallback(object, timerCallbacks);
    });
}

// ── Property get ──
static int widget_index(lua_State* L) {
    auto* lw = checkWidget(L, 1);
    const char* key = luaL_checkstring(L, 2);
    auto* w = lw->widget;

    if (!strcmp(key, "Caption") || !strcmp(key, "Text")) {
        if (auto* btn = qobject_cast<QPushButton*>(w)) { lua_pushstring(L, btn->text().toUtf8()); return 1; }
        if (auto* lbl = qobject_cast<QLabel*>(w)) { lua_pushstring(L, lbl->text().toUtf8()); return 1; }
        if (auto* ed = qobject_cast<QLineEdit*>(w)) { lua_pushstring(L, ed->text().toUtf8()); return 1; }
        if (auto* list = qobject_cast<QListWidget*>(w)) {
            auto* item = list->currentItem();
            lua_pushstring(L, item ? item->text().toUtf8().constData() : "");
            return 1;
        }
        lua_pushstring(L, w->windowTitle().toUtf8()); return 1;
    }
    if (!strcmp(key, "Width")) { lua_pushinteger(L, w->width()); return 1; }
    if (!strcmp(key, "Height")) { lua_pushinteger(L, w->height()); return 1; }
    if (!strcmp(key, "Visible")) { lua_pushboolean(L, w->isVisible()); return 1; }
    if (!strcmp(key, "Enabled")) {
        lua_pushboolean(L, lw->timer ? lw->timer->isActive() : w->isEnabled());
        return 1;
    }
    if (!strcmp(key, "Checked")) {
        if (auto* cb = qobject_cast<QCheckBox*>(w)) { lua_pushboolean(L, cb->isChecked()); return 1; }
    }
    if (!strcmp(key, "Count")) {
        if (auto* list = qobject_cast<QListWidget*>(w)) { lua_pushinteger(L, list->count()); return 1; }
    }
    if (!strcmp(key, "Interval") && lw->timer) { lua_pushinteger(L, lw->timer->interval()); return 1; }

    // Method: show, close
    if (!strcmp(key, "show")) {
        lua_pushcfunction(L, [](lua_State* L) -> int { checkWidget(L, 1)->widget->show(); return 0; });
        return 1;
    }
    if (!strcmp(key, "close")) {
        lua_pushcfunction(L, [](lua_State* L) -> int { checkWidget(L, 1)->widget->close(); return 0; });
        return 1;
    }
    if (!strcmp(key, "showModal")) {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* w = checkWidget(L, 1)->widget;
            if (auto* dlg = qobject_cast<QDialog*>(w)) dlg->exec();
            else w->show();
            return 0;
        });
        return 1;
    }
    if (!strcmp(key, "addItem")) {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* w = checkWidget(L, 1)->widget;
            auto* list = qobject_cast<QListWidget*>(w);
            if (list) list->addItem(luaL_checkstring(L, 2));
            return 0;
        });
        return 1;
    }
    if (!strcmp(key, "clear")) {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* w = checkWidget(L, 1)->widget;
            if (auto* list = qobject_cast<QListWidget*>(w)) list->clear();
            return 0;
        });
        return 1;
    }

    lua_pushnil(L);
    return 1;
}

// ── Property set ──
static int widget_newindex(lua_State* L) {
    auto* lw = checkWidget(L, 1);
    const char* key = luaL_checkstring(L, 2);
    auto* w = lw->widget;

    if (!strcmp(key, "Caption") || !strcmp(key, "Text")) {
        const char* val = luaL_checkstring(L, 3);
        if (auto* btn = qobject_cast<QPushButton*>(w)) btn->setText(val);
        else if (auto* lbl = qobject_cast<QLabel*>(w)) lbl->setText(val);
        else if (auto* ed = qobject_cast<QLineEdit*>(w)) ed->setText(val);
        else if (auto* list = qobject_cast<QListWidget*>(w)) {
            if (auto* item = list->currentItem()) item->setText(val);
        }
        else w->setWindowTitle(val);
        return 0;
    }
    if (!strcmp(key, "Width")) { w->resize(luaL_checkinteger(L, 3), w->height()); return 0; }
    if (!strcmp(key, "Height")) { w->resize(w->width(), luaL_checkinteger(L, 3)); return 0; }
    if (!strcmp(key, "Visible")) { w->setVisible(lua_toboolean(L, 3)); return 0; }
    if (!strcmp(key, "Enabled")) {
        if (lw->timer) {
            if (lua_toboolean(L, 3)) lw->timer->start();
            else lw->timer->stop();
        } else {
            w->setEnabled(lua_toboolean(L, 3));
        }
        return 0;
    }
    if (!strcmp(key, "Checked")) {
        if (auto* cb = qobject_cast<QCheckBox*>(w)) cb->setChecked(lua_toboolean(L, 3));
        return 0;
    }
    if (!strcmp(key, "Interval") && lw->timer) { lw->timer->setInterval(luaL_checkinteger(L, 3)); return 0; }

    // Event handlers
    if (!strcmp(key, "OnClick")) {
        clearCallback(w, clickCallbacks);
        if (lua_isnil(L, 3))
            return 0;
        luaL_checktype(L, 3, LUA_TFUNCTION);
        int ref = storeCallback(L, 3);
        CallbackBinding binding;
        binding.ref = ref;
        if (auto* btn = qobject_cast<QPushButton*>(w)) {
            binding.connection = QObject::connect(btn, &QPushButton::clicked, [ref, w]() {
                invokeLuaCallback(ref, w);
            });
            clickCallbacks[w] = binding;
            return 0;
        } else if (auto* cb = qobject_cast<QCheckBox*>(w)) {
            binding.connection = QObject::connect(cb, &QCheckBox::toggled, [ref, w]() {
                invokeLuaCallback(ref, w);
            });
            clickCallbacks[w] = binding;
            return 0;
        }
        unrefCallback(ref);
        return 0;
    }
    if (!strcmp(key, "OnChange")) {
        clearCallback(w, changeCallbacks);
        if (lua_isnil(L, 3))
            return 0;
        luaL_checktype(L, 3, LUA_TFUNCTION);
        int ref = storeCallback(L, 3);
        CallbackBinding binding;
        binding.ref = ref;
        if (auto* ed = qobject_cast<QLineEdit*>(w)) {
            binding.connection = QObject::connect(ed, &QLineEdit::textChanged, [ref, w]() {
                invokeLuaCallback(ref, w);
            });
            changeCallbacks[w] = binding;
            return 0;
        } else if (auto* cb = qobject_cast<QCheckBox*>(w)) {
            binding.connection = QObject::connect(cb, &QCheckBox::toggled, [ref, w]() {
                invokeLuaCallback(ref, w);
            });
            changeCallbacks[w] = binding;
            return 0;
        } else if (auto* list = qobject_cast<QListWidget*>(w)) {
            binding.connection = QObject::connect(list, &QListWidget::currentRowChanged, [ref, w]() {
                invokeLuaCallback(ref, w);
            });
            changeCallbacks[w] = binding;
            return 0;
        }
        unrefCallback(ref);
        return 0;
    }
    if (!strcmp(key, "OnClose")) {
        clearCallback(w, closeCallbacks);
        if (lua_isnil(L, 3))
            return 0;
        luaL_checktype(L, 3, LUA_TFUNCTION);
        int ref = storeCallback(L, 3);
        CallbackBinding binding;
        binding.ref = ref;
        binding.connection = QObject::connect(w, &QObject::destroyed, [ref, w]() {
            invokeLuaCallback(ref, nullptr);
            unrefCallback(ref);
            closeCallbacks.erase(w);
        });
        closeCallbacks[w] = binding;
        return 0;
    }
    if (!strcmp(key, "OnTimer") && lw->timer) {
        clearCallback(lw->timer, timerCallbacks);
        if (lua_isnil(L, 3))
            return 0;
        luaL_checktype(L, 3, LUA_TFUNCTION);
        int ref = storeCallback(L, 3);
        CallbackBinding binding;
        binding.ref = ref;
        binding.connection = QObject::connect(lw->timer, &QTimer::timeout, [ref, w, timer = lw->timer]() {
            invokeLuaCallback(ref, w, timer);
        });
        timerCallbacks[lw->timer] = binding;
        return 0;
    }

    return 0;
}

// ── Widget creation functions ──

static QWidget* getParentWidget(lua_State* L, int idx) {
    if (lua_isuserdata(L, idx)) {
        auto* lw = (LuaWidget*)luaL_testudata(L, idx, WIDGET_MT);
        if (lw) return lw->widget;
    }
    return nullptr;
}

static int l_createForm(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* w = new QWidget(parent);
    w->setWindowTitle("Form");
    w->resize(400, 300);
    w->setAttribute(Qt::WA_DeleteOnClose);
    w->setLayout(new QVBoxLayout);
    trackDestroyed(w);
    pushWidget(L, w);
    return 1;
}

static int l_createButton(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* btn = new QPushButton("Button", parent);
    if (parent && parent->layout()) parent->layout()->addWidget(btn);
    trackDestroyed(btn);
    pushWidget(L, btn);
    return 1;
}

static int l_createLabel(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* lbl = new QLabel("Label", parent);
    if (parent && parent->layout()) parent->layout()->addWidget(lbl);
    trackDestroyed(lbl);
    pushWidget(L, lbl);
    return 1;
}

static int l_createEdit(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* ed = new QLineEdit(parent);
    if (parent && parent->layout()) parent->layout()->addWidget(ed);
    trackDestroyed(ed);
    pushWidget(L, ed);
    return 1;
}

static int l_createCheckBox(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* cb = new QCheckBox("CheckBox", parent);
    if (parent && parent->layout()) parent->layout()->addWidget(cb);
    trackDestroyed(cb);
    pushWidget(L, cb);
    return 1;
}

static int l_createListView(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* list = new QListWidget(parent);
    if (parent && parent->layout()) parent->layout()->addWidget(list);
    trackDestroyed(list);
    pushWidget(L, list);
    return 1;
}

static int l_createTimer(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    int enabledIndex = 1;
    if (lua_isuserdata(L, 1) || lua_isnil(L, 1))
        enabledIndex = 2;
    bool enabled = !lua_isnoneornil(L, enabledIndex) && lua_toboolean(L, enabledIndex);

    auto* timer = new QTimer(parent);
    timer->setInterval(1000);
    // Timer doesn't have a visual widget, but we wrap it as one for property access
    auto* dummy = new QWidget(parent); // Hidden
    dummy->hide();
    trackDestroyed(dummy);
    trackDestroyed(timer);
    if (enabled)
        timer->start();
    pushWidget(L, dummy, timer);
    return 1;
}

static int l_getProperty(lua_State* L) {
    return widget_index(L);
}

static int l_setProperty(lua_State* L) {
    return widget_newindex(L);
}

// ── Registration ──

void registerLuaGuiBindings(lua_State* L) {
    guiLuaState = L;

    // Create the CEWidget metatable
    luaL_newmetatable(L, WIDGET_MT);
    lua_pushcfunction(L, widget_index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, widget_newindex);
    lua_setfield(L, -2, "__newindex");
    lua_pop(L, 1);

    // Register creation functions
    lua_register(L, "createForm", l_createForm);
    lua_register(L, "createButton", l_createButton);
    lua_register(L, "createLabel", l_createLabel);
    lua_register(L, "createEdit", l_createEdit);
    lua_register(L, "createCheckBox", l_createCheckBox);
    lua_register(L, "createListView", l_createListView);
    lua_register(L, "createTimer", l_createTimer);
    lua_register(L, "getProperty", l_getProperty);
    lua_register(L, "setProperty", l_setProperty);
}

} // namespace ce
