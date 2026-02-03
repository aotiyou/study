package cn.com.zxy.obj;

/**
 * @author infosec
 * @since 2025/11/6
 */
public abstract class Parent extends Base {

    protected String parent;

    protected void setParent() {
        this.parent = "111111111";
    }

    protected void parentMethod() {
        System.out.println("parent = " + parent);
    }

}
