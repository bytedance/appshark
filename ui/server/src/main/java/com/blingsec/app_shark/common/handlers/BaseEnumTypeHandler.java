package com.blingsec.app_shark.common.handlers;

import com.blingsec.app_shark.common.base.BaseEnum;
import com.blingsec.app_shark.common.enums.AssignmentProcessStatus;
import com.blingsec.app_shark.common.enums.IsFlag;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedTypes;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Objects;

@MappedTypes(value = {IsFlag.class, AssignmentProcessStatus.class})
public class BaseEnumTypeHandler<E extends Enum<E> & BaseEnum> extends BaseTypeHandler<E> {

    private Class<E> type;

    public BaseEnumTypeHandler() {
    }

    public BaseEnumTypeHandler(Class<E> type) {
        this.type = type;
    }

    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, E parameter, JdbcType jdbcType) throws SQLException {
        if (jdbcType == null) {
            ps.setInt(i, parameter.getCode());
        } else {
            ps.setObject(i, parameter.getCode(), jdbcType.TYPE_CODE);
        }
    }

    @Override
    public E getNullableResult(ResultSet rs, String columnName) throws SQLException {
        return this.get(rs.getString(columnName));
    }

    @Override
    public E getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        return this.get(rs.getString(columnIndex));
    }

    @Override
    public E getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        return this.get(cs.getString(columnIndex));
    }

    private <E extends Enum<E> & BaseEnum> E get(String v) {
        if (StringUtils.isBlank(v)) {
            return null;
        }
        return (E) this.get(type, v);
    }

    private <E extends Enum<E> & BaseEnum> E get(Class<E> type, String v) {
        List<E> enumList = EnumUtils.getEnumList(type);
        for (E e : enumList) {
            if (Objects.equals(e.getCode(), Integer.parseInt(v))) {
                return e;
            }
        }
        return null;
    }
}