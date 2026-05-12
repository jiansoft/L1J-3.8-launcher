# yiwei 範圍技能傷害封包修改說明

## 目的

讓 yiwei Java 版 `S_RangeSkill` 在每個範圍技能目標後額外送出該目標的實際傷害，供已修改的登入器或客戶端解析顯示。

修改後的 target 欄位格式：

```text
repeat targetCount:
  D targetObjectId
  H hitFlag
  D damage
```

原版 3.80C client 不支援此格式；使用此修改後，client parser 或登入器必須同步支援新版 target stride。

## 需要修改的檔案

```text
l1j_yiwei_java/src/com/lineage/server/model/skill/TargetStatus.java
l1j_yiwei_java/src/com/lineage/server/model/skill/L1SkillUse.java
l1j_yiwei_java/src/com/lineage/server/model/skill/L1SkillUse2.java
l1j_yiwei_java/src/com/lineage/server/serverpackets/S_RangeSkill.java
```

## 1. 修改 TargetStatus.java

在 `TargetStatus` 類別內新增 damage 欄位與 getter/setter：

```java
private int _damage = 0;

public int getDamage() {
	return this._damage;
}

public void setDamage(final int damage) {
	this._damage = damage;
}
```

建議放在 `_isCalc` 欄位附近。

## 2. 修改 L1SkillUse.java

找到 `runSkill()` 裡處理 `_targetList` 的迴圈：

```java
for (final Iterator<TargetStatus> iter = _targetList.iterator(); iter.hasNext();) {
	ts = null;
	cha = null;
	isSuccess = false;
	undeadType = 0;
	ts = iter.next();
	cha = ts.getTarget();
```

在取得 `ts` 後先清除舊傷害：

```java
ts.setDamage(0);
```

修改後：

```java
for (final Iterator<TargetStatus> iter = _targetList.iterator(); iter.hasNext();) {
	ts = null;
	cha = null;
	isSuccess = false;
	undeadType = 0;
	ts = iter.next();
	cha = ts.getTarget();
	ts.setDamage(0);
```

接著找到 commit 傷害的位置：

```java
if ((this._dmg != 0) || (drainMana != 0)) {
	magic.commit(this._dmg, drainMana);
}
```

在 `magic.commit()` 前寫入本目標傷害：

```java
ts.setDamage(this._dmg);

if ((this._dmg != 0) || (drainMana != 0)) {
	magic.commit(this._dmg, drainMana);
}
```

## 3. 修改 L1SkillUse2.java

`L1SkillUse2.java` 有另一份技能流程，修改方式與 `L1SkillUse.java` 相同。

同樣在 `_targetList` 迴圈取得 `ts` 後加入：

```java
ts.setDamage(0);
```

同樣在 `magic.commit(this._dmg, drainMana);` 前加入：

```java
ts.setDamage(this._dmg);
```

## 4. 修改 S_RangeSkill.java

找到 target loop：

```java
for (TargetStatus target : targetList) {
	int targetobj = target.getTarget().getId();

	this.writeD(targetobj);

	if (target.isCalc()) {
		this.writeH(0x20);
	} else {
		this.writeH(0x00);
	}
}
```

在 `hitFlag` 後追加 damage：

```java
for (TargetStatus target : targetList) {
	int targetobj = target.getTarget().getId();

	this.writeD(targetobj);

	if (target.isCalc()) {
		this.writeH(0x20);
	} else {
		this.writeH(0x00);
	}

	this.writeD(target.getDamage());
}
```

## 修改後封包格式

完整 `S_RangeSkill` 格式：

```text
C opcode
C actionId
D casterId
H casterX
H casterY
C heading
D sequence
H gfxId
C rangeType
H reserved
H targetCount

repeat targetCount:
  D targetObjectId
  H hitFlag
  D damage
```

其中：

- `hitFlag = 0x20` 表示命中或有計算。
- `hitFlag = 0x00` 表示未命中或不計算。
- `damage` 為 `int32`，little-endian。
- 範圍技能通常是一個目標一筆傷害，不需要 hitCount。

## 客戶端解析提醒

修改後每個 target 長度從 6 bytes 變成 10 bytes。

原本：

```text
D targetObjectId
H hitFlag
```

新版：

```text
D targetObjectId
H hitFlag
D damage
```

client 或登入器 parser 必須同步改為新版格式，否則第二個目標開始會解析錯位。
