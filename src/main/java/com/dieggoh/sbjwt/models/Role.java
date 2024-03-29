package com.dieggoh.sbjwt.models;

import javax.persistence.*;

@Entity
@Table(name = "roles", schema = "testjwt")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole name;

    public Role() {
    }

    public Role(ERole name) {
        this.name = name;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public ERole getName() {
        return name;
    }

    public void setName(ERole name) {
        this.name = name;
    }

    @Override
    public String toString(){
        final StringBuilder sb = new StringBuilder("Role {");
        sb.append("id=").append(id);
        sb.append(", name=").append(name);
        return sb.toString();
    }

}
