package com.blingsec.app_shark.pojo.qo;

import lombok.Data;
import lombok.ToString;

import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.List;

@Data
@ToString
public class IdsQo implements Serializable {
    public IdsQo() {
    }

    public IdsQo(List<Integer> ids) {
        this.ids = ids;
    }

    @NotNull
    List<Integer> ids;
}
