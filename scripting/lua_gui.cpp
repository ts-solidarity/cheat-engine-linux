/// Lua GUI bindings — create Qt6 widgets from Lua.
/// Supports: createForm, createButton, createLabel, createEdit, createCheckBox, createTimer
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
#include <QTimer>
#include <QVBoxLayout>
#include <QApplication>
#include <unordered_map>
#include <string>
#include <functional>

namespace ce {

// Store Lua callback references per widget
static std::unordered_map<QObject*, int> luaCallbacks; // widget → Lua registry ref
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

// ── Property get ──
static int widget_index(lua_State* L) {
    auto* lw = checkWidget(L, 1);
    const char* key = luaL_checkstring(L, 2);
    auto* w = lw->widget;

    if (!strcmp(key, "Caption") || !strcmp(key, "Text")) {
        if (auto* btn = qobject_cast<QPushButton*>(w)) { lua_pushstring(L, btn->text().toUtf8()); return 1; }
        if (auto* lbl = qobject_cast<QLabel*>(w)) { lua_pushstring(L, lbl->text().toUtf8()); return 1; }
        if (auto* ed = qobject_cast<QLineEdit*>(w)) { lua_pushstring(L, ed->text().toUtf8()); return 1; }
        lua_pushstring(L, w->windowTitle().toUtf8()); return 1;
    }
    if (!strcmp(key, "Width")) { lua_pushinteger(L, w->width()); return 1; }
    if (!strcmp(key, "Height")) { lua_pushinteger(L, w->height()); return 1; }
    if (!strcmp(key, "Visible")) { lua_pushboolean(L, w->isVisible()); return 1; }
    if (!strcmp(key, "Enabled")) { lua_pushboolean(L, w->isEnabled()); return 1; }
    if (!strcmp(key, "Checked")) {
        if (auto* cb = qobject_cast<QCheckBox*>(w)) { lua_pushboolean(L, cb->isChecked()); return 1; }
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
        else w->setWindowTitle(val);
        return 0;
    }
    if (!strcmp(key, "Width")) { w->resize(luaL_checkinteger(L, 3), w->height()); return 0; }
    if (!strcmp(key, "Height")) { w->resize(w->width(), luaL_checkinteger(L, 3)); return 0; }
    if (!strcmp(key, "Visible")) { w->setVisible(lua_toboolean(L, 3)); return 0; }
    if (!strcmp(key, "Enabled")) { w->setEnabled(lua_toboolean(L, 3)); return 0; }
    if (!strcmp(key, "Checked")) {
        if (auto* cb = qobject_cast<QCheckBox*>(w)) cb->setChecked(lua_toboolean(L, 3));
        return 0;
    }
    if (!strcmp(key, "Interval") && lw->timer) { lw->timer->setInterval(luaL_checkinteger(L, 3)); return 0; }

    // Event handlers
    if (!strcmp(key, "OnClick") && lua_isfunction(L, 3)) {
        lua_pushvalue(L, 3);
        int ref = luaL_ref(L, LUA_REGISTRYINDEX);
        luaCallbacks[w] = ref;
        if (auto* btn = qobject_cast<QPushButton*>(w)) {
            QObject::connect(btn, &QPushButton::clicked, [ref]() {
                if (!guiLuaState) return;
                lua_rawgeti(guiLuaState, LUA_REGISTRYINDEX, ref);
                lua_pcall(guiLuaState, 0, 0, 0);
            });
        }
        if (auto* cb = qobject_cast<QCheckBox*>(w)) {
            QObject::connect(cb, &QCheckBox::toggled, [ref]() {
                if (!guiLuaState) return;
                lua_rawgeti(guiLuaState, LUA_REGISTRYINDEX, ref);
                lua_pcall(guiLuaState, 0, 0, 0);
            });
        }
        return 0;
    }
    if (!strcmp(key, "OnTimer") && lw->timer && lua_isfunction(L, 3)) {
        lua_pushvalue(L, 3);
        int ref = luaL_ref(L, LUA_REGISTRYINDEX);
        QObject::connect(lw->timer, &QTimer::timeout, [ref]() {
            if (!guiLuaState) return;
            lua_rawgeti(guiLuaState, LUA_REGISTRYINDEX, ref);
            lua_pcall(guiLuaState, 0, 0, 0);
        });
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
    pushWidget(L, w);
    return 1;
}

static int l_createButton(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* btn = new QPushButton("Button", parent);
    if (parent && parent->layout()) parent->layout()->addWidget(btn);
    pushWidget(L, btn);
    return 1;
}

static int l_createLabel(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* lbl = new QLabel("Label", parent);
    if (parent && parent->layout()) parent->layout()->addWidget(lbl);
    pushWidget(L, lbl);
    return 1;
}

static int l_createEdit(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* ed = new QLineEdit(parent);
    if (parent && parent->layout()) parent->layout()->addWidget(ed);
    pushWidget(L, ed);
    return 1;
}

static int l_createCheckBox(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* cb = new QCheckBox("CheckBox", parent);
    if (parent && parent->layout()) parent->layout()->addWidget(cb);
    pushWidget(L, cb);
    return 1;
}

static int l_createTimer(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* timer = new QTimer(parent);
    // Timer doesn't have a visual widget, but we wrap it as one for property access
    auto* dummy = new QWidget(parent); // Hidden
    dummy->hide();
    pushWidget(L, dummy, timer);
    return 1;
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
    lua_register(L, "createTimer", l_createTimer);
}

} // namespace ce
